package cluster

import (
	"fmt"
	"os"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// readFillObjectPool reads ObjectPool fill data and captures entries.
// Per pool: ReadUnsigned(length) + length × (ReadByte(entry_bits) + type-dependent data).
//
// <=3.2: TypeBits[0:7] (7 bits), PatchableBit[7]. The enum values are not
// stable across that whole era: Dart 2.10 has kNativeEntryData at type 4;
// 2.12-2.14 have no type 4; 2.15-3.2 use types 3/4 for switchable/megamorphic
// entry-point resets. Dart 3.2 also swaps Tagged/Immediate (handled below).
//
//	0=kTaggedObject→ReadRef, 1=kImmediate→Read<intptr_t>, 2+=nothing.
//
// >=3.3: TypeBits[0:4], PatchableBit[4], SnapshotBehaviorBits[5:8].
//
//	behavior 0: 0=kImmediate→Read<intptr_t>, 1=kTaggedObject→ReadRef, 2=kNativeFunction→nothing.
//	behavior 1 (kNotSnapshotable): invalid in a serialized snapshot.
//	behavior 2,3,4: reset/set values, no payload bytes.
func readFillObjectPool(s *dartfmt.Stream, cm *ClusterMeta, profile *snapshot.VersionProfile, fillRefUnsigned bool) ([]PoolEntry, error) {
	oldPoolFormat := profile.OldPoolFormat
	poolTypeSwapped := profile.PoolTypeSwapped
	if debugFill {
		saved := s.Position()
		rawBytes, _ := s.ReadBytes(40)
		s.SetPosition(saved)
		fmt.Fprintf(os.Stderr, "  ObjectPool fill start @0x%x raw=%x\n", saved, rawBytes)
	}
	var entries []PoolEntry
	idx := 0
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("pool %d/%d length: %w", i, cm.Count, err)
		}
		if err := validateFillLength(cm, i, length, "object_pool"); err != nil {
			return nil, err
		}
		for j := int64(0); j < length; j++ {
			entryBits, err := s.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("pool %d entry %d bits: %w", i, j, err)
			}

			pe := PoolEntry{Index: idx}
			idx++

			if oldPoolFormat {
				// ≤3.2: TypeBits = entryBits & 0x7F (7 bits).
				typeBits := entryBits & 0x7F
				// v3.2 swapped kImmediate(0) and kTaggedObject(1). Normalize to pre-3.2 ordering.
				if poolTypeSwapped && typeBits <= 1 {
					typeBits ^= 1
				}
				switch typeBits {
				case 0: // kTaggedObject → ReadRef
					ref, err := readRef(s, fillRefUnsigned)
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d ref (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolTagged
					pe.RefID = int(ref)
				case 1: // kImmediate → Read<intptr_t> = Read64
					imm, err := s.ReadTagged64()
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d imm (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolImmediate
					pe.Imm = imm
				case 2: // kNativeFunction → nothing
					pe.Kind = PoolNative
				case 3:
					// 2.10-2.14: kNativeFunctionWrapper; 2.15-3.2:
					// kSwitchableCallMissEntryPoint. Neither writes payload bytes.
					pe.Kind = PoolNative
				case 4:
					switch {
					case profile.PreCanonicalSplit:
						// Dart 2.10 only: kNativeEntryData carries one ref.
						ref, err := readRef(s, fillRefUnsigned)
						if err != nil {
							return nil, fmt.Errorf("pool %d entry %d native_entry_data ref (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
						}
						pe.Kind = PoolTagged
						pe.RefID = int(ref)
					case snapshot.VersionAtLeast(profile.DartVersion, "2.15.0"):
						// 2.15-3.2: kMegamorphicCallEntryPoint, reset by the
						// deserializer and therefore carries no payload bytes.
						pe.Kind = PoolNative
					default:
						// 2.12-2.14 have only entry types 0..3. Do not reinterpret
						// a malformed type-4 byte using the older 2.10 layout.
						return nil, fmt.Errorf("pool %d entry %d: type 4 is invalid for Dart %s", i, j, profile.DartVersion)
					}
				default:
					return nil, fmt.Errorf("pool %d entry %d: unknown type %d (bits=0x%02x pos=0x%x)", i, j, typeBits, entryBits, s.Position())
				}
			} else {
				// v3.x: SnapshotBehaviorBits = entryBits >> 5 (3 bits).
				behaviorBits := entryBits >> 5
				typeBits := entryBits & 0x0F
				switch behaviorBits {
				case 0: // kSnapshotable
					switch typeBits {
					case 0: // kImmediate → Read<intptr_t>
						imm, err := s.ReadTagged64()
						if err != nil {
							return nil, fmt.Errorf("pool %d entry %d imm: %w", i, j, err)
						}
						pe.Kind = PoolImmediate
						pe.Imm = imm
					case 1: // kTaggedObject → ReadRef
						ref, err := readRef(s, fillRefUnsigned)
						if err != nil {
							return nil, fmt.Errorf("pool %d entry %d ref: %w", i, j, err)
						}
						pe.Kind = PoolTagged
						pe.RefID = int(ref)
					case 2: // kNativeFunction → nothing
						pe.Kind = PoolNative
					default:
						return nil, fmt.Errorf("pool %d entry %d: unknown type %d", i, j, typeBits)
					}
				case 1:
					// kNotSnapshotable is ASSERTed away by the SDK serializer.
					// Accepting it as a zero-payload reset value would make a
					// forged pool entry look valid.
					return nil, fmt.Errorf("pool %d entry %d: kNotSnapshotable entry cannot appear in a snapshot", i, j)
				case 2, 3, 4: // reset/bootstrap/switchable or set-to-zero: no payload
					pe.Kind = PoolEmpty
				default:
					return nil, fmt.Errorf("pool %d entry %d: unknown snapshot behavior %d", i, j, behaviorBits)
				}
			}
			entries = append(entries, pe)
		}
	}
	return entries, nil
}
