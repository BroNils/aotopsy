package analysis

import (
	"fmt"
	"sort"

	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
)

type DartClassLayout struct {
	ClassName    string            `json:"class_name"`
	ClassID      int32             `json:"class_id"`
	InstanceSize int32             `json:"instance_size"`
	Fields       []DartFieldLayout `json:"fields"`
}

// DartFieldLayout is one instance slot in a DartClassLayout.
//
// One entry per slot, always -- not one entry per surviving Field object.
// That is the shape the SDK's own snapshot analyzer emits, and its comment
// says why:
//
//	Here we write information about every slot in an instance. Even if
//	there's no corresponding [Field] object, we will write out an entry
//	describing the slot (e.g. whether it's boxed or not, ...). So this
//	information is always available, whereas the "fields" above only writes
//	non-tree shaken [Field] objects.
//	                -- analyze_snapshot_api_impl.cc:139-144
//
// AOTopsy used to emit either the surviving Fields OR, for a class with none,
// a placeholder per word -- so a class with some surviving Fields silently
// omitted every tree-shaken slot, and 95% of classes (1823 of 1913 on
// dart-3.12.2-arm64) got nothing but anonymous `f_0x…`.
type DartFieldLayout struct {
	Name       string `json:"name"`
	ByteOffset int32  `json:"byte_offset"`
	// IsReference distinguishes a tagged pointer slot from a raw machine
	// word, out of the class's unboxed-fields bitmap. The SDK analyzer emits
	// the same bit as "is_reference"; AOTopsy had the bitmap and used it only
	// to parse Instance fill data, never to describe the layout.
	IsReference bool `json:"is_reference"`
	// SlotType is "type_arguments_field" for the slot holding the instance's
	// TypeArguments pointer, "instance_field" when a Field object named it,
	// and "unknown_slot" when the Field was tree-shaken. Same vocabulary as
	// the SDK analyzer.
	SlotType string `json:"slot_type"`
}

const (
	slotTypeArguments = "type_arguments_field"
	slotInstanceField = "instance_field"
	slotUnknown       = "unknown_slot"
)

// BuildClassLayouts recovers each class's instance layout, one entry per slot.
//
// Slot range follows the SDK analyzer: from the superclass's next-field offset
// (or the start of the object's own fields, when there is no superclass) up to
// this class's next-field offset, so a layout describes what the class ADDS
// rather than repeating everything it inherits.
func BuildClassLayouts(result *cluster.Result, pl *naming.PoolLookups, compressedPtrs bool) []DartClassLayout {
	var wordSize int32 = 8
	if compressedPtrs {
		wordSize = 4
	}

	// Field objects that survived tree shaking, by owning class ref.
	type resolvedField struct {
		nameRefID  int
		byteOffset int32
	}
	fieldsByOwner := make(map[int][]resolvedField)
	for _, fi := range result.Fields {
		if fi.OwnerRefID <= 0 || fi.HostOffset < 0 {
			continue
		}
		wordOff, ok := result.MintValues[int(fi.HostOffset)]
		if !ok {
			continue
		}
		fieldsByOwner[fi.OwnerRefID] = append(fieldsByOwner[fi.OwnerRefID], resolvedField{
			nameRefID:  fi.NameRefID,
			byteOffset: int32(wordOff) * wordSize,
		})
	}

	// super_type is a ref to a Type, whose ClassID identifies the superclass.
	// Walking that chain lets an inherited slot be named by the class that
	// declared it, instead of appearing as an anonymous word.
	classByID := make(map[int32]*cluster.ClassInfo, len(result.Classes))
	for i := range result.Classes {
		classByID[result.Classes[i].ClassID] = &result.Classes[i]
	}
	typeByRef := make(map[int]*cluster.TypeInfo, len(result.Types))
	for i := range result.Types {
		typeByRef[result.Types[i].RefID] = &result.Types[i]
	}
	superOf := func(ci *cluster.ClassInfo) *cluster.ClassInfo {
		if ci.SuperTypeRefID < 0 {
			return nil
		}
		ti, ok := typeByRef[ci.SuperTypeRefID]
		if !ok {
			return nil
		}
		return classByID[ti.ClassID]
	}

	var layouts []DartClassLayout
	for _, ci := range result.Classes {
		if ci.InstanceSize <= 0 {
			continue
		}
		className := ""
		if ci.NameRefID >= 0 {
			if s, ok := pl.RefToStr[ci.NameRefID]; ok {
				className = s
			}
		}
		if className == "" {
			continue
		}

		layout := DartClassLayout{
			ClassName:    className,
			ClassID:      ci.ClassID,
			InstanceSize: ci.InstanceSize * wordSize,
		}

		// Named slots by byte offset, gathered from this class AND every
		// superclass. An inherited field occupies a slot in this instance, so
		// a layout that omitted it would describe a struct nobody can apply --
		// which is what flutter_meta.json's consumers do with it.
		namedAt := make(map[int32]string)
		for c, depth := &ci, 0; c != nil && depth < 64; depth++ {
			for _, rf := range fieldsByOwner[c.RefID] {
				if _, taken := namedAt[rf.byteOffset]; taken {
					continue // the most-derived declaration wins
				}
				name := ""
				if rf.nameRefID >= 0 {
					if s, ok := pl.RefToStr[rf.nameRefID]; ok {
						name = s
					}
					if name == "" {
						if s, ok := pl.VmRefToStr[rf.nameRefID]; ok {
							name = s
						}
					}
				}
				if name == "" {
					name = fmt.Sprintf("field_0x%x", rf.byteOffset)
				}
				namedAt[rf.byteOffset] = name
			}
			c = superOf(c)
		}

		typeArgsOff, hasTypeArgs := ci.TypeArgsByteOffset(wordSize)

		// Every slot of the instance, header excluded. Not just the ones this
		// class declares: the artifact is a struct description, and an
		// inherited slot is part of the struct.
		endWords := ci.NextFieldOff
		if endWords <= 0 || endWords > ci.InstanceSize {
			// NextFieldOff is not captured on every version; the instance
			// size is the honest upper bound then.
			endWords = ci.InstanceSize
		}

		for w := int32(1); w < endWords; w++ {
			off := w * wordSize
			slot := DartFieldLayout{
				ByteOffset:  off,
				IsReference: !unboxedAt(ci.UnboxedFieldBitmap, w),
			}
			switch {
			case hasTypeArgs && off == typeArgsOff:
				slot.Name = slotTypeArguments
				slot.SlotType = slotTypeArguments
				// The type-arguments slot always holds a pointer.
				slot.IsReference = true
			case namedAt[off] != "":
				slot.Name = namedAt[off]
				slot.SlotType = slotInstanceField
			default:
				slot.Name = fmt.Sprintf("f_0x%x", off)
				slot.SlotType = slotUnknown
			}
			layout.Fields = append(layout.Fields, slot)
		}

		sort.Slice(layout.Fields, func(i, j int) bool {
			return layout.Fields[i].ByteOffset < layout.Fields[j].ByteOffset
		})
		layouts = append(layouts, layout)
	}
	return layouts
}

// unboxedAt reports whether the slot at word index w holds a raw machine word.
//
// The bitmap is a uint64 indexed by word offset from the object start, so it
// describes the first 64 slots and nothing beyond; the VM treats anything past
// that as a reference, and so does this.
func unboxedAt(bitmap uint64, word int32) bool {
	if bitmap == 0 || word < 0 || word >= 64 {
		return false
	}
	return bitmap&(1<<uint(word)) != 0
}
