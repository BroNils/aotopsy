package sdk

// RecognizedIntrinsic holds metadata for a compiler-recognized method or intrinsic.
// Source: runtime/vm/compiler/recognized_methods_list.h @3.12.2
type RecognizedIntrinsic struct {
	LibraryName  string
	ClassName    string
	FunctionName string
	EnumName     string
	Description  string
}

// RecognizedMethods maps recognized signatures to their intrinsic metadata.
var RecognizedMethods = map[string]RecognizedIntrinsic{
	"_BigIntImpl._lsh": {
		LibraryName:  "core",
		ClassName:    "_BigIntImpl",
		FunctionName: "_lsh",
		EnumName:     "BigInt_lsh",
		Description:  "BigInt left bitwise shift",
	},
	"_BigIntImpl._rsh": {
		LibraryName:  "core",
		ClassName:    "_BigIntImpl",
		FunctionName: "_rsh",
		EnumName:     "BigInt_rsh",
		Description:  "BigInt right bitwise shift",
	},
	"_BigIntImpl._multiply": {
		LibraryName:  "core",
		ClassName:    "_BigIntImpl",
		FunctionName: "_multiply",
		EnumName:     "BigInt_multiply",
		Description:  "BigInt multiplication",
	},
	"_StringBase._interpolate": {
		LibraryName:  "core",
		ClassName:    "_StringBase",
		FunctionName: "_interpolate",
		EnumName:     "StringBaseInterpolate",
		Description:  "String interpolation",
	},
	"_StringBase.substring": {
		LibraryName:  "core",
		ClassName:    "_StringBase",
		FunctionName: "substring",
		EnumName:     "StringBaseSubstring",
		Description:  "String substring extraction",
	},
	"_Utf8Decoder.convert": {
		LibraryName:  "convert",
		ClassName:    "_Utf8Decoder",
		FunctionName: "convert",
		EnumName:     "Utf8DecoderConvert",
		Description:  "UTF-8 byte stream decoding",
	},
	"_Double.sin": {
		LibraryName:  "math",
		ClassName:    "_Double",
		FunctionName: "sin",
		EnumName:     "DoubleSin",
		Description:  "Trigonometric sine",
	},
	"_Double.cos": {
		LibraryName:  "math",
		ClassName:    "_Double",
		FunctionName: "cos",
		EnumName:     "DoubleCos",
		Description:  "Trigonometric cosine",
	},
	"_Double.sqrt": {
		LibraryName:  "math",
		ClassName:    "_Double",
		FunctionName: "sqrt",
		EnumName:     "DoubleSqrt",
		Description:  "Square root",
	},
	"_Hash._jenkins": {
		LibraryName:  "core",
		ClassName:    "_Hash",
		FunctionName: "_jenkins",
		EnumName:     "HashJenkins",
		Description:  "Jenkins hash function",
	},
}

// LookupRecognizedIntrinsic returns the recognized intrinsic metadata if the function is recognized.
func LookupRecognizedIntrinsic(qualifiedName string) (RecognizedIntrinsic, bool) {
	for k, v := range RecognizedMethods {
		if k == qualifiedName || (v.ClassName != "" && v.FunctionName != "" && (qualifiedName == v.ClassName+"."+v.FunctionName || qualifiedName == v.ClassName+"::"+v.FunctionName)) {
			return v, true
		}
	}
	return RecognizedIntrinsic{}, false
}
