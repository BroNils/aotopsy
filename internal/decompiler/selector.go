package decompiler

import "strings"

// selectorTable is a static catalog mapping a normalized selector name to
// a fully-qualified semantic path, used as the fallback when no richer
// pool/owner-class hint is available for a call site. Ported (a curated
// subset, not the full 112-entry set) from flutterdec's
// helpers/selector_table/categories.rs 6 static arrays -- same shape
// (normalized-key -> "category:qualified.path" string pairs), same
// matching algorithm (candidates.go / matching.go below).
var selectorTable = map[string]string{
	// --- Flutter framework (framework:flutter.*) ---
	"build":                 "framework:flutter.widgets.Widget.build",
	"setstate":              "framework:flutter.widgets.State.setState",
	"initstate":             "framework:flutter.widgets.State.initState",
	"dispose":               "framework:flutter.widgets.State.dispose",
	"didupdatewidget":       "framework:flutter.widgets.State.didUpdateWidget",
	"didchangedependencies": "framework:flutter.widgets.State.didChangeDependencies",
	"createstate":           "framework:flutter.widgets.StatefulWidget.createState",
	"createelement":         "framework:flutter.widgets.Widget.createElement",
	"markneedsbuild":        "framework:flutter.widgets.Element.markNeedsBuild",
	"performlayout":         "framework:flutter.rendering.RenderObject.performLayout",
	"paint":                 "framework:flutter.rendering.RenderObject.paint",
	"markneedslayout":       "framework:flutter.rendering.RenderObject.markNeedsLayout",
	"markneedspaint":        "framework:flutter.rendering.RenderObject.markNeedsPaint",
	"addlistener":           "framework:flutter.foundation.ChangeNotifier.addListener",
	"removelistener":        "framework:flutter.foundation.ChangeNotifier.removeListener",
	"notifylisteners":       "framework:flutter.foundation.ChangeNotifier.notifyListeners",
	"of":                    "framework:flutter.widgets.InheritedWidget.of",
	"navigate":              "framework:flutter.widgets.Navigator.push",
	"push":                  "framework:flutter.widgets.Navigator.push",
	"pop":                   "framework:flutter.widgets.Navigator.pop",
	"scheduleframe":         "framework:flutter.scheduler.SchedulerBinding.scheduleFrame",
	"handledrawframe":       "framework:flutter.scheduler.SchedulerBinding.handleDrawFrame",
	"attach":                "framework:flutter.rendering.RenderObject.attach",
	"detach":                "framework:flutter.rendering.RenderObject.detach",

	// --- dart:core (stdlib:dart.core.*) ---
	"tostring":      "stdlib:dart.core.Object.toString",
	"hashcode":      "stdlib:dart.core.Object.hashCode",
	"compareto":     "stdlib:dart.core.Comparable.compareTo",
	"indexof":       "stdlib:dart.core.String.indexOf",
	"substring":     "stdlib:dart.core.String.substring",
	"split":         "stdlib:dart.core.String.split",
	"trim":          "stdlib:dart.core.String.trim",
	"tolowercase":   "stdlib:dart.core.String.toLowerCase",
	"touppercase":   "stdlib:dart.core.String.toUpperCase",
	"startswith":    "stdlib:dart.core.String.startsWith",
	"endswith":      "stdlib:dart.core.String.endsWith",
	"contains":      "stdlib:dart.core.String.contains",
	"replaceall":    "stdlib:dart.core.String.replaceAll",
	"isempty":       "stdlib:dart.core.String.isEmpty",
	"isnotempty":    "stdlib:dart.core.String.isNotEmpty",
	"length":        "stdlib:dart.core.String.length",
	"add":           "stdlib:dart.core.List.add",
	"addall":        "stdlib:dart.core.List.addAll",
	"remove":        "stdlib:dart.core.List.remove",
	"removeat":      "stdlib:dart.core.List.removeAt",
	"clear":         "stdlib:dart.core.List.clear",
	"map":           "stdlib:dart.core.Iterable.map",
	"where":         "stdlib:dart.core.Iterable.where",
	"foreach":       "stdlib:dart.core.Iterable.forEach",
	"tolist":        "stdlib:dart.core.Iterable.toList",
	"first":         "stdlib:dart.core.Iterable.first",
	"last":          "stdlib:dart.core.Iterable.last",
	"parse":         "stdlib:dart.core.int.parse",
	"parsedouble":   "stdlib:dart.core.double.parse",
	"toradixstring": "stdlib:dart.core.int.toRadixString",

	// --- dart:async (stdlib:dart.async.*) ---
	"then":          "stdlib:dart.async.Future.then",
	"catcherror":    "stdlib:dart.async.Future.catchError",
	"whencomplete":  "stdlib:dart.async.Future.whenComplete",
	"complete":      "stdlib:dart.async.Completer.complete",
	"completeerror": "stdlib:dart.async.Completer.completeError",
	"listen":        "stdlib:dart.async.Stream.listen",
	"cancel":        "stdlib:dart.async.StreamSubscription.cancel",
	"asstream":      "stdlib:dart.async.Future.asStream",
	"delayed":       "stdlib:dart.async.Future.delayed",
	"wait":          "stdlib:dart.async.Future.wait",

	// --- dart:io (stdlib:dart.io.*) ---
	"readasstring":  "stdlib:dart.io.File.readAsString",
	"writeasstring": "stdlib:dart.io.File.writeAsString",
	"exists":        "stdlib:dart.io.File.exists",

	// --- dart:typed_data / VM internals (stdlib:dart.typed_data.*) ---
	"setint64":   "stdlib:dart.typed_data.ByteData.setInt64",
	"getint64":   "stdlib:dart.typed_data.ByteData.getInt64",
	"setuint8":   "stdlib:dart.typed_data.ByteData.setUint8",
	"getuint8":   "stdlib:dart.typed_data.ByteData.getUint8",
	"getfloat32": "stdlib:dart.typed_data.ByteData.getFloat32",
	"getfloat64": "stdlib:dart.typed_data.ByteData.getFloat64",

	// --- VM runtime (runtime:dart_vm.*) ---
	"new":         "runtime:dart_vm.Closure.new",
	"invoke":      "runtime:dart_vm.Function.invoke",
	"runtimetype": "runtime:dart_vm.Object.runtimeType",
}

// classifyStandardSelector generates all normalized-candidate forms of a
// raw selector string and returns the first table match found (suffixed
// " [selector]", matching flutterdec's classify_standard_selector), or ""
// if no candidate matches.
func classifyStandardSelector(raw string) string {
	for _, cand := range selectorCandidates(raw) {
		if path, ok := selectorTable[cand]; ok {
			return path + " [selector]"
		}
	}
	return ""
}

// selectorCandidates builds candidate normalized forms: the fully
// alphanumeric-stripped lowercase form, each alphanumeric word token, and
// (for every candidate so far) variants stripping a leading init/get/set/
// native/_ prefix -- mirrors flutterdec's helpers/selector_table/
// candidates.rs selector_candidates.
func selectorCandidates(raw string) []string {
	base := stripNonAlnum(strings.ToLower(raw))
	seen := map[string]bool{}
	var out []string
	add := func(c string) {
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	add(base)
	for _, w := range alnumWords(strings.ToLower(raw)) {
		add(w)
	}
	// Expand prefix-stripped variants over everything collected so far.
	initial := append([]string(nil), out...)
	for _, c := range initial {
		for _, prefix := range []string{"init", "native", "_"} {
			if strings.HasPrefix(c, prefix) {
				add(strings.TrimPrefix(c, prefix))
			}
		}
		if strings.HasPrefix(c, "get") {
			add(strings.TrimPrefix(c, "get"))
		}
		if strings.HasPrefix(c, "set") {
			add(c) // keep "setXxx" itself too
			add(strings.TrimPrefix(c, "set"))
		}
	}
	return out
}

func stripNonAlnum(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func alnumWords(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}

// looksConstructorLikeSelector mirrors flutterdec's
// looks_constructor_like_selector: starts uppercase, has a later
// uppercase letter, isn't all-caps/digits/underscore-ish.
func looksConstructorLikeSelector(s string) bool {
	if s == "" || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	hasLower := false
	for i, r := range s {
		if i == 0 {
			continue
		}
		if r >= 'a' && r <= 'z' {
			hasLower = true
		}
	}
	return hasLower
}
