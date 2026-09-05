package cluster

import (
	"fmt"
	"os"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// readFillCode reads Code fill data, extracting owner refs and instruction metadata.
// AOT PRODUCT: ReadInstructions + N ReadRef per code.
// v2.16+: ReadInstructions = 1 ReadUnsigned (payload_info). 6 refs.
// v2.10-v2.15: ReadInstructions = 2 ReadUnsigned (text_offset_delta + payload_info). 7 refs.
// Deferred codes skip ReadInstructions (no stream read).
// Ref 0 = owner (Function/Closure/FfiTrampolineData).
// instrIdxBase is the running instructions_index_ counter from previous Code clusters.
//
// stateBitsAfterRef: 0 = no state_bits in fill (v2.10, v2.14+).
// N>0 = state_bits is read after first N refs (v2.13: N=1). DiscardedBit (bit 3)
// of state_bits determines whether remaining refs are skipped.
func readFillCode(s *dartfmt.Stream, cm *ClusterMeta, ct *snapshot.CIDTable, fillRefUnsigned bool, instrIdxBase int, codeNumRefs int, textOffsetDelta bool, stateBitsAfterRef int, stateBitsAtEnd bool, hasIndexRefs bool) ([]CodeEntry, error) {
	// Dart 3.13.0+: the Code cluster's ReadFill opens with two ReadRefId
	// values before the per-Code loop --
	//
	//	d->set_lazy_compile_index(d->ReadRefId());
	//	d->set_unknown_dart_code_index(d->ReadRefId());
	//
	// (CodeDeserializationCluster::ReadFill @3.13.0). They are cluster-level,
	// not per-object, so they are read exactly once here. Skipping them would
	// shift every Code record by two refs.
	if hasIndexRefs {
		if _, err := s.ReadRefId(); err != nil {
			return nil, fmt.Errorf("code lazy_compile_index: %w", err)
		}
		if _, err := s.ReadRefId(); err != nil {
			return nil, fmt.Errorf("code unknown_dart_code_index: %w", err)
		}
	}
	numRefs := codeNumRefs
	if numRefs == 0 {
		numRefs = 6 // default: owner, exception_handlers, pc_descriptors, catch_entry, inlined_id_to_function, code_source_map
	}
	codes := make([]CodeEntry, 0, cm.Count)
	ref := cm.StartRef
	instrIdx := instrIdxBase
	discardedCount := 0
	// Mirrors Deserializer::previous_text_offset_, which persists across the
	// whole cluster (v2.10-v2.15 bare-instructions AOT).
	var runningTextOffset int64
	for i := int64(0); i < cm.Count; i++ {
		var payloadInfo int64
		var textOff int64
		clusterIndex := -1
		traceCode := debugFill && i < 5

		// v2.14+: discarded status from alloc phase. v2.13: determined from state_bits below.
		discarded := cm.DiscardedCodes[i]

		posStart := s.Position()

		// Dump raw bytes for first 3, last 3, and codes near known failure points.
		if debugFill && (i < 3 || i >= cm.Count-3 || (i >= 21600 && i <= 21610)) {
			saved := s.Position()
			hexBytes, _ := s.ReadBytes(30)
			s.SetPosition(saved)
			fmt.Fprintf(os.Stderr, "  code[%d] RAW@0x%x: %x\n", i, posStart, hexBytes)
		}

		// Main (non-deferred) codes: ReadInstructions reads payload data.
		// v2.10-v2.15: ReadUnsigned(text_offset_delta) + ReadUnsigned(payload_info).
		//   v2.14+: discarded codes also read compressed_stackmaps(ReadRef) in ReadInstructions.
		// v2.16+: ReadUnsigned(payload_info) only.
		// Deferred codes: ReadInstructions does nothing (early return).
		if i < cm.MainCount {
			if textOffsetDelta {
				tod, err := s.ReadUnsigned()
				if err != nil {
					return codes, fmt.Errorf("code %d/%d text_offset_delta: %w", i, cm.Count, err)
				}
				// The value is a DELTA against a running total, not this
				// Code's offset. Deserializer::ReadInstructions at 2.12.0:
				//
				//	previous_text_offset_ += ReadUnsigned();
				//	const uword payload_start =
				//	    image_reader_->GetBareInstructionsAt(previous_text_offset_);
				//
				// Storing the raw delta gave 7714 Code objects only 409
				// distinct "offsets" (851 of them 0), so ranges collapsed
				// onto each other, 95% got size 0 and were skipped, and the
				// whole 2.x pipeline ran on ~5% of the binary.
				runningTextOffset += tod
				textOff = runningTextOffset
			}
			pi, err := s.ReadUnsigned()
			if err != nil {
				return codes, fmt.Errorf("code %d/%d payload_info: %w", i, cm.Count, err)
			}
			payloadInfo = pi
			clusterIndex = instrIdx
			instrIdx++

			// v2.14+: discarded codes read compressed_stackmaps ref inside ReadInstructions,
			// then return without reading any other refs or state_bits.
			if discarded && stateBitsAfterRef == 0 {
				if _, err := readRef(s, fillRefUnsigned); err != nil {
					return codes, fmt.Errorf("code %d/%d discarded compressed_stackmaps: %w", i, cm.Count, err)
				}
			}
		}

		// v2.13 (stateBitsAfterRef > 0): compressed_stackmaps → state_bits → [if discarded: stop] → 6 refs.
		// All codes read compressed_stackmaps and state_bits. DiscardedBit (bit 3) of state_bits
		// determines whether remaining refs are read. This is different from v2.14+ where
		// discarded status comes from the alloc phase.
		var ownerRef int
		var excHandlersRef int = -1
		var pcDescRef int = -1
		var csmRef int = -1
		var inlinedFuncsRef int = -1
		var compressedStackMapsRef int = -1
		if stateBitsAfterRef > 0 {
			// Read first N refs (before state_bits) — all codes, including discarded.
			// In v2.13, stateBitsAfterRef=1: ref 0 is compressed_stackmaps_
			// (moved before state_bits so the discarded bit can be checked
			// before reading the remaining refs). Verified against SDK
			// clustered_snapshot.cc @2.12.0: compressed_stackmaps_ is the
			// ref immediately before state_bits in the 2.13 interleaved layout.
			for j := 0; j < stateBitsAfterRef; j++ {
				r, err := readRef(s, fillRefUnsigned)
				if err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
				if j == 0 && numRefs == 7 {
					// v2.13: ref 0 (before state_bits) is compressed_stackmaps_.
					compressedStackMapsRef = int(r)
				}
			}
			// Read state_bits (Read<int32_t> VLE).
			sbPos := s.Position()
			sb, err := s.ReadTagged32()
			if err != nil {
				// Dump context for diagnosis.
				if debugFill {
					fmt.Fprintf(os.Stderr, "  code[%d] state_bits ERR at pos=0x%x (code start=0x%x)\n", i, sbPos, posStart)
					// Dump raw bytes from code start.
					saved := s.Position()
					s.SetPosition(posStart)
					hexBytes, _ := s.ReadBytes(40)
					s.SetPosition(saved)
					fmt.Fprintf(os.Stderr, "  hex@0x%x=%x\n", posStart, hexBytes)
				}
				return codes, fmt.Errorf("code %d/%d state_bits: %w", i, cm.Count, err)
			}
			if debugFill && (i%1000 == 0 || (i >= 21595 && i <= 21610)) {
				fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x sb=0x%x discarded=%v cumDisc=%d\n",
					i, posStart, sb, (sb>>3)&1 != 0, discardedCount)
			}
			// DiscardedBit = bit 3 of state_bits.
			discarded = (sb>>3)&1 != 0
			if discarded {
				discardedCount++
				if traceCode {
					fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x state_bits=0x%x DISCARDED\n", i, posStart, sb)
				}
				goto done
			}
			// Read remaining refs after state_bits.
			// v2.13 ref order after state_bits: owner(1), exception_handlers(2),
			// pc_descriptors(3), catch_entry(4), inlined_id_to_function(5),
			// code_source_map(6).
			for j := stateBitsAfterRef; j < numRefs; j++ {
				r, err := readRef(s, fillRefUnsigned)
				if err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
				// Owner is the first ref after state_bits (e.g., ref[1] for v2.13).
				if j == stateBitsAfterRef {
					ownerRef = int(r)
				}
				if j == stateBitsAfterRef+1 {
					excHandlersRef = int(r)
				}
				if j == stateBitsAfterRef+2 {
					pcDescRef = int(r)
				}
				// In 2.x (numRefs==7), inlined_id_to_function_ is at ref 5
				// and code_source_map_ at ref 6. In 3.x (numRefs==6) these
				// are at ref 4 and 5 respectively, but 3.x does not use the
				// stateBitsAfterRef path.
				if numRefs == 7 {
					if j == stateBitsAfterRef+4 {
						inlinedFuncsRef = int(r)
					}
					if j == stateBitsAfterRef+5 {
						csmRef = int(r)
					}
				}
			}
		} else if !discarded {
			// v2.10, v2.14+: read all refs in order (no interleaved state_bits).
			// v2.10/v2.12/v2.14-v2.15 (CodeNumRefs=7, 2.x AOT with bare_instructions):
			//   owner(0), exception_handlers(1), pc_descriptors(2), catch_entry(3),
			//   compressed_stackmaps(4), inlined_id_to_function(5), code_source_map(6).
			//   Verified against SDK clustered_snapshot.cc @2.12.0.
			// v3.x (CodeNumRefs=6, 3.x AOT):
			//   owner(0), exception_handlers(1), pc_descriptors(2), catch_entry(3),
			//   inlined_id_to_function(4), code_source_map(5).
			//   object_pool and compressed_stackmaps are null (not refs) in 3.x AOT.
			for j := 0; j < numRefs; j++ {
				r, err := readRef(s, fillRefUnsigned)
				if err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
				if j == 0 {
					ownerRef = int(r)
				}
				if j == 1 {
					excHandlersRef = int(r)
				}
				if j == 2 {
					pcDescRef = int(r)
				}
				if numRefs == 7 {
					// Dart 2.10-2.15 AOT: compressed_stackmaps_ is a ref at
					// index 4, inlined_id_to_function_ at 5, code_source_map_
					// at 6. Not "2.x" -- 2.16.0 moved compressed_stackmaps_
					// behind `kind() == kFullJIT` (app_snapshot.cc), so
					// 2.16-2.19 have six refs like 3.x. The numRefs == 7 test
					// is what encodes that; CodeNumRefs is set for exactly
					// 2.10.0-2.15.0.
					if j == 4 {
						compressedStackMapsRef = int(r)
					}
					if j == 5 {
						inlinedFuncsRef = int(r)
					}
					if j == 6 {
						csmRef = int(r)
					}
				} else {
					// 3.x AOT: inlined_id_to_function_ at 4, code_source_map_ at 5.
					if j == 4 {
						inlinedFuncsRef = int(r)
					}
					if j == 5 {
						csmRef = int(r)
					}
				}
			}
		}

		// v2.10: state_bits_ = Read<int32_t>() after ALL refs, unconditionally (no discarded check).
		if stateBitsAtEnd {
			if _, err := s.ReadTagged32(); err != nil {
				return codes, fmt.Errorf("code %d/%d state_bits_at_end: %w", i, cm.Count, err)
			}
		}

	done:
		if traceCode {
			fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x total=%d discarded=%v\n",
				i, posStart, s.Position()-posStart, discarded)
		}
		if debugFill && (i < 5 || i >= cm.Count-3 || i == cm.MainCount-1 || i == cm.MainCount || i%5000 == 0) {
			fmt.Fprintf(os.Stderr, "  code[%d/%d] main=%d owner=%d discarded=%v endPos=0x%x\n", i, cm.Count, cm.MainCount, ownerRef, discarded, s.Position())
		}
		codes = append(codes, CodeEntry{
			RefID:                  ref,
			OwnerRef:               ownerRef,
			ClusterIndex:           clusterIndex,
			PayloadInfo:            payloadInfo,
			TextOffset:             textOff,
			ExceptionHandlersRef:   excHandlersRef,
			PcDescriptorsRef:       pcDescRef,
			CodeSourceMapRef:       csmRef,
			InlinedFuncsRef:        inlinedFuncsRef,
			CompressedStackMapsRef: compressedStackMapsRef,
		})
		ref++
	}
	if debugFill && discardedCount > 0 {
		fmt.Fprintf(os.Stderr, "  code: %d/%d discarded (from state_bits)\n", discardedCount, cm.Count)
	}
	return codes, nil
}

// readFillObjectPool reads ObjectPool fill data and captures entries.
// Per pool: ReadUnsigned(length) + length × (ReadByte(entry_bits) + type-dependent data).
//
// v2.17.6: TypeBits[0:7] (7 bits), PatchableBit[7].
//
//	0=kTaggedObject→ReadRef, 1=kImmediate→Read<intptr_t>, 2+=nothing.
//
// v3.x: TypeBits[0:4], PatchableBit[4], SnapshotBehaviorBits[5:8].
//
//	behavior 0: 0=kImmediate→Read<intptr_t>, 1=kTaggedObject→ReadRef, 2=kNativeFunction→nothing.
//	behavior 1,2,3: nothing.
