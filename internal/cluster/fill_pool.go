package cluster

import (
	"fmt"
	"os"

	"aotopsy/internal/dartfmt"
)

func readFillObjectPool(s *dartfmt.Stream, cm *ClusterMeta, oldPoolFormat, poolTypeSwapped, fillRefUnsigned bool) ([]PoolEntry, error) {
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
				case 2, 3: // kNativeFunction, kNativeFunctionWrapper → nothing
					pe.Kind = PoolNative
				case 4: // kNativeEntryData → ReadRef (same as kTaggedObject)
					ref, err := readRef(s, fillRefUnsigned)
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d native_entry_data ref (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolTagged
					pe.RefID = int(ref)
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
				case 1, 2, 3, 4: // kResetToBootstrapNative, kResetToSwitchableCallMissEntryPoint, kSetToZero, kResetToMegamorphicCallEntryPoint
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
