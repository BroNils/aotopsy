package decompiler

import "strings"

var dartLibWhitelist = map[string]bool{
	"core": true, "async": true, "collection": true, "convert": true,
	"io": true, "isolate": true, "math": true, "typed": true, "ffi": true,
	"developer": true,
}

// inferCallIntentFromSymbolName decodes an already-structured raw symbol
// name (as aotopsy's own naming/canonicalization would produce, e.g.
// "dart_core_String_substring") into a semantic intent path. Mirrors
// flutterdec's helpers/call_intent/intent.rs infer_call_intent.
func inferCallIntentFromSymbolName(name string) string {
	switch {
	case strings.HasPrefix(name, "dart_"):
		rest := strings.Split(strings.TrimPrefix(name, "dart_"), "_")
		if len(rest) < 2 || !dartLibWhitelist[rest[0]] {
			return ""
		}
		lib := rest[0]
		tail := rest[1:]
		if len(tail) >= 2 && startsUpper(tail[0]) {
			return "stdlib:dart." + lib + "." + tail[0] + "." + strings.Join(tail[1:], "_")
		}
		return "stdlib:dart." + lib + "." + strings.Join(tail, "_")
	case strings.HasPrefix(name, "flutter_"):
		return decodeSegmentedIntent(name, "flutter_", "framework:flutter.")
	case strings.HasPrefix(name, "package_"):
		return decodeSegmentedIntent(name, "package_", "package:")
	case strings.HasPrefix(name, "vm_runtime_"):
		return "runtime:dart_vm." + strings.TrimPrefix(name, "vm_runtime_")
	case strings.HasPrefix(name, "native_libc_"):
		return "native:libc." + strings.TrimPrefix(name, "native_libc_")
	case strings.HasPrefix(name, "native_android_log_"):
		return "native:android.log." + strings.TrimPrefix(name, "native_android_log_")
	}
	return ""
}

// decodeSegmentedIntent handles the flutter_/package_ underscore-segment
// shape: "<prefix><lib>_..._<Owner>_<method>" -> "<qualPrefix><lib>.
// <Owner>.<method>", finding the owner by scanning backward for the last
// uppercase-starting segment (mirrors the Rust owner-detection heuristic).
func decodeSegmentedIntent(name, prefix, qualPrefix string) string {
	rest := strings.Split(strings.TrimPrefix(name, prefix), "_")
	if len(rest) < 2 {
		return ""
	}
	lib := rest[0]
	ownerIdx := -1
	for i := len(rest) - 1; i >= 1; i-- {
		if startsUpper(rest[i]) {
			ownerIdx = i
			break
		}
	}
	if ownerIdx < 0 || ownerIdx == len(rest)-1 {
		return qualPrefix + lib + "." + strings.Join(rest[1:], "_")
	}
	owner := rest[ownerIdx]
	method := strings.Join(rest[ownerIdx+1:], "_")
	return qualPrefix + lib + "." + owner + "." + method
}

func startsUpper(s string) bool {
	return s != "" && s[0] >= 'A' && s[0] <= 'Z'
}

// isGenericSymbolPlaceholder recognizes unhelpful auto-generated names,
// matching flutterdec's is_generic_symbol_placeholder.
func isGenericSymbolPlaceholder(name string) bool {
	if name == "" || name == "unknown" {
		return true
	}
	for _, p := range []string{"sub_", "fn_0x", "nullsub_", "loc_", "off_", "fun_"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// resolveCallIntent is the priority chain flutterdec's emit_call uses:
// raw-symbol-name decoding -> selector-table fallback. Returns "" if none
// apply.
func resolveCallIntent(symbolName, selectorHint string) string {
	if symbolName != "" && !isGenericSymbolPlaceholder(symbolName) {
		if intent := inferCallIntentFromSymbolName(symbolName); intent != "" {
			return intent
		}
	}
	if selectorHint != "" {
		if intent := classifyStandardSelector(selectorHint); intent != "" {
			return intent
		}
	}
	return ""
}

// fallbackCallNameFromSelector mirrors flutterdec's
// fallback_call_name_from_selector: `<Selector>.new(...)` for
// constructor-shaped selectors, else `dispatch.<selector>(...)`.
func fallbackCallNameFromSelector(selector string) string {
	if selector == "" {
		return ""
	}
	if looksConstructorLikeSelector(selector) {
		return selector + ".new"
	}
	return "dispatch." + selector
}
