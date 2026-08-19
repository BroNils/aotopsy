package pipeline

import (
	"os"
	"testing"
)

// TestNamedParamNames_Chain verifies named-parameter recovery against a real
// Flutter build, end to end:
//
//	Function.signature -> FunctionType.named_parameter_names (Array)
//	                   -> Strings
//
// Three SDK facts decide whether this is right or merely plausible, and each
// gets its own assertion below because each was violated by the first
// implementation:
//
//  1. The array only holds names when packed_parameter_counts'
//     HasNamedOptionalParameters bit is set (raw_object.h@3.12.2 bit 1).
//     Optional POSITIONAL parameters leave it empty -- object.cc@3.12.2
//     FinalizeNameArray asserts `named_parameter_names() == empty_array()`
//     when NumOptionalNamedParameters() == 0.
//
//  2. The array is longer than the name count: Smi flag slots holding
//     required-ness bits follow the name Strings. FunctionType::
//     HasRequiredNamedParameters tests exactly that
//     (`parameter_names.Length() > num_named_params`). Reading past
//     NumOptional resolves Smis as strings and yields "?" garbage.
//
//  3. Names are indexed `index - num_fixed_parameters()`
//     (object.cc@3.12.2 FunctionType::ParameterNameAt), where the SDK's
//     num_fixed_parameters INCLUDES the implicit receiver.
//
// A Flutter app is a good witness because the framework is saturated with
// named parameters -- every widget constructor has them.
func TestNamedParamNames_Chain(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	res := clusterOnly(t, libPath)
	if len(res.FuncTypes) == 0 {
		t.Fatal("no FunctionType objects captured")
	}
	pl := BuildPoolLookups(res, nil, nil, true, "", false)
	r := NewTypeParamResolver(res, pl)

	var (
		named, positionalOptional int
		resolved, withNames       int
		unknownNames              int
		sample                    []string
	)
	for i := range res.FuncTypes {
		ft := res.FuncTypes[i]
		if ft.NumOptional == 0 {
			continue
		}
		if !ft.HasNamedOptional {
			positionalOptional++
			// Fact 1: a positional-optional signature has no names to give.
			if got := r.NamedParamNames(ft); got != nil {
				t.Errorf("FunctionType %d has optional POSITIONAL parameters "+
					"but NamedParamNames returned %v; positional parameter "+
					"names are not stored in an AOT snapshot at all",
					ft.RefID, got)
			}
			continue
		}
		named++

		got := r.NamedParamNames(ft)
		if got == nil {
			continue
		}
		resolved++

		// Fact 3: the slice covers the WHOLE parameter list, so its length is
		// num_fixed (receiver included) + num_optional.
		numFixed := ft.NumFixed
		if ft.HasImplicit {
			numFixed++
		}
		if want := numFixed + ft.NumOptional; len(got) != want {
			t.Errorf("FunctionType %d: len = %d, want %d "+
				"(num_fixed %d incl. receiver + num_optional %d)",
				ft.RefID, len(got), want, numFixed, ft.NumOptional)
			continue
		}
		// Positional slots carry no name; only the named tail does.
		for j := 0; j < numFixed; j++ {
			if got[j] != "" {
				t.Errorf("FunctionType %d: positional slot %d named %q -- "+
					"named parameters must start at index num_fixed (%d)",
					ft.RefID, j, got[j], numFixed)
			}
		}
		for j := numFixed; j < len(got); j++ {
			if got[j] == "" {
				t.Errorf("FunctionType %d: named slot %d is empty", ft.RefID, j)
			}
			// Fact 2: reading into the Smi flag slots is what produces "?".
			if got[j] == "?" {
				unknownNames++
			}
		}
		if got[numFixed] != "" && got[numFixed] != "?" {
			withNames++
			if len(sample) < 8 {
				sample = append(sample, got[numFixed])
			}
		}
	}

	if named == 0 {
		t.Fatal("no FunctionType has named optional parameters; a Flutter build " +
			"is full of them, so the HasNamedOptionalParameters bit (packed_" +
			"parameter_counts bit 1) is almost certainly being read wrong")
	}
	if positionalOptional == 0 {
		t.Error("every optional parameter in the binary reads as NAMED, which is " +
			"implausible -- Dart code uses [positional] optionals too. Bit 1 is " +
			"likely being confused with another field.")
	}
	if withNames == 0 {
		t.Fatalf("%d FunctionTypes have named parameters but not one name "+
			"resolved to a string", named)
	}
	// The Smi flag slots are the trap: if they were being read as names, a
	// large share of entries would come back "?" rather than a handful whose
	// String simply is not in the app-isolate table.
	if unknownNames*2 > withNames {
		t.Errorf("%d of %d resolved named parameters are %q -- that is the "+
			"signature of reading past NumOptional into the required-ness Smi "+
			"flag slots", unknownNames, withNames, "?")
	}
	t.Logf("named-optional signatures: %d (%d resolved), positional-optional: %d; "+
		"first names: %v", named, resolved, positionalOptional, sample)
}
