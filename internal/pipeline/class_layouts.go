package pipeline

import (
	"fmt"
	"sort"

	"aotopsy/internal/cluster"
)

type DartClassLayout struct {
	ClassName    string            `json:"class_name"`
	ClassID      int32             `json:"class_id"`
	InstanceSize int32             `json:"instance_size"`
	Fields       []DartFieldLayout `json:"fields"`
}

// DartFieldLayout is one field in a DartClassLayout.
type DartFieldLayout struct {
	Name       string `json:"name"`
	ByteOffset int32  `json:"byte_offset"`
}

// BuildClassLayouts joins ClassInfo + FieldInfo + string lookups into class layouts.
func BuildClassLayouts(result *cluster.Result, pl *PoolLookups, compressedPtrs bool) []DartClassLayout {
	var wordSize int32 = 8
	if compressedPtrs {
		wordSize = 4
	}

	type resolvedField struct {
		nameRefID  int
		byteOffset int32
	}
	fieldsByOwner := make(map[int][]resolvedField)
	for _, fi := range result.Fields {
		if fi.OwnerRefID <= 0 || fi.HostOffset < 0 {
			continue
		}
		offsetRef := int(fi.HostOffset)
		wordOff, ok := result.MintValues[offsetRef]
		if !ok {
			continue
		}
		fieldsByOwner[fi.OwnerRefID] = append(fieldsByOwner[fi.OwnerRefID], resolvedField{
			nameRefID:  fi.NameRefID,
			byteOffset: int32(wordOff) * wordSize,
		})
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

		if rfs, ok := fieldsByOwner[ci.RefID]; ok {
			for _, rf := range rfs {
				fieldName := ""
				if rf.nameRefID >= 0 {
					if s, ok := pl.RefToStr[rf.nameRefID]; ok {
						fieldName = s
					}
				}
				if fieldName == "" {
					if s, ok := pl.VmRefToStr[rf.nameRefID]; ok {
						fieldName = s
					}
				}
				if fieldName == "" {
					fieldName = fmt.Sprintf("field_0x%x", rf.byteOffset)
				}
				layout.Fields = append(layout.Fields, DartFieldLayout{
					Name:       fieldName,
					ByteOffset: rf.byteOffset,
				})
			}
		} else {
			byteSize := ci.InstanceSize * wordSize
			for off := wordSize; off+wordSize <= byteSize; off += wordSize {
				layout.Fields = append(layout.Fields, DartFieldLayout{
					Name:       fmt.Sprintf("f_0x%x", off),
					ByteOffset: off,
				})
			}
		}

		sort.Slice(layout.Fields, func(i, j int) bool {
			return layout.Fields[i].ByteOffset < layout.Fields[j].ByteOffset
		})

		layouts = append(layouts, layout)
	}
	return layouts
}
