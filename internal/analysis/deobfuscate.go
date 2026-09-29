package analysis

import (
	"sort"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/naming"
)

// DeobfuscatedClassRecord holds inferred semantic identity for an obfuscated class.
type DeobfuscatedClassRecord struct {
	ObfuscatedName string   `json:"obfuscated_name"`
	ClassID        int      `json:"class_id"`
	SuperClassName string   `json:"super_class_name,omitempty"`
	PredictedRole  string   `json:"predicted_role"`
	Confidence     float64  `json:"confidence"` // 0.0 - 1.0
	Clues          []string `json:"clues,omitempty"`
}

// BuildDeobfuscationMap analyzes class topology, superclasses, and string references
// to infer the original semantic roles of obfuscated classes.
func BuildDeobfuscationMap(cl *cluster.Result, pl *naming.PoolLookups, stringRefs []disasm.StringRefRecord) []DeobfuscatedClassRecord {
	if cl == nil || pl == nil {
		return nil
	}

	// A class name is only library-local in Dart. The disassembly artifact's
	// function display name intentionally omits the library URL, so `a.login`
	// cannot identify which class `a` owns it when more than one library has an
	// `a`. Never let a name collision turn one class's endpoint into evidence for
	// every other class with the same obfuscated name.
	classNameCount := make(map[string]int, len(cl.Classes))
	for _, ci := range cl.Classes {
		if name := pl.RefToStr[ci.NameRefID]; name != "" {
			classNameCount[name]++
		}
	}

	// Map an unambiguous class display name to string references accessed by its
	// methods. Ambiguous owners are deliberately excluded until the producer
	// carries a stable class/library identity rather than only a display string.
	stringsByOwner := make(map[string][]string)
	for _, sr := range stringRefs {
		dot := strings.IndexByte(sr.Func, '.')
		if dot <= 0 {
			continue
		}
		owner := sr.Func[:dot]
		if classNameCount[owner] != 1 {
			continue
		}
		stringsByOwner[owner] = append(stringsByOwner[owner], sr.Value)
	}
	typeByRef := make(map[int]cluster.TypeInfo, len(cl.Types))
	for _, ti := range cl.Types {
		typeByRef[ti.RefID] = ti
	}

	var records []DeobfuscatedClassRecord
	for _, ci := range cl.Classes {
		name := pl.RefToStr[ci.NameRefID]
		if name == "" {
			continue
		}

		// Only process short/obfuscated class names (1-3 chars)
		isObfuscated := len(name) <= 3 && !strings.HasPrefix(name, "_")
		if !isObfuscated {
			continue
		}

		superName := ""
		if ci.SuperTypeRefID >= 0 {
			if ti, ok := typeByRef[ci.SuperTypeRefID]; ok && ti.ClassID > 0 {
				superName = ClassNameByCID(ti.ClassID, cl, pl, pl.CT)
				if superName == "<unnamed>" {
					superName = ""
				}
			}
		}

		var clues []string
		predictedRole := "Unknown"
		confidence := 0.0

		if superName != "" {
			clues = append(clues, "inherits from "+superName)
			if strings.Contains(superName, "ChangeNotifier") || strings.Contains(superName, "Bloc") || strings.Contains(superName, "Cubit") {
				predictedRole = "State Controller / ViewModel"
				confidence = 0.85
			} else if strings.Contains(superName, "StatelessWidget") || strings.Contains(superName, "StatefulWidget") {
				predictedRole = "UI Component / Widget"
				confidence = 0.90
			} else if strings.Contains(superName, "State") {
				predictedRole = "Widget State Lifecycle"
				confidence = 0.85
			}
		}

		// Check accessed strings
		if accessed, ok := stringsByOwner[name]; ok && len(accessed) > 0 {
			for _, s := range accessed {
				if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.Contains(s, "/api/") {
					clues = append(clues, "references endpoint: "+s)
					predictedRole = "API Client / Network Repository"
					confidence = 0.95
					break
				}
			}
		}

		records = append(records, DeobfuscatedClassRecord{
			ObfuscatedName: name,
			ClassID:        int(ci.ClassID),
			SuperClassName: superName,
			PredictedRole:  predictedRole,
			Confidence:     confidence,
			Clues:          clues,
		})
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].ClassID < records[j].ClassID
	})

	return records
}
