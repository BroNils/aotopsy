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

	// Map class ID -> string references accessed by its methods
	stringsByOwner := make(map[string][]string)
	for _, sr := range stringRefs {
		if sr.Func != "" {
			parts := strings.Split(sr.Func, ".")
			if len(parts) > 1 {
				owner := parts[0]
				stringsByOwner[owner] = append(stringsByOwner[owner], sr.Value)
			}
		}
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
			superName = resolveRefName(pl, ci.SuperTypeRefID)
		}

		var clues []string
		predictedRole := "Entity / Data Model"
		confidence := 0.5

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
