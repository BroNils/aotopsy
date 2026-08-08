package decompiler

import "strings"

// selectorTable is a static catalog mapping a normalized selector name to
// a fully-qualified semantic path, used as the fallback when no richer
// pool/owner-class hint is available for a call site. Ported from
// flutterdec's helpers/selector_table/categories.rs — full 166-entry set.
var selectorTable = map[string]string{
	// --- Flutter framework (framework:flutter.*) ---
	"build":                 "framework:flutter.widgets.Widget.build",
	"setstate":              "framework:flutter.widgets.State.setState",
	"initstate":             "framework:flutter.widgets.State.initState",
	"dispose":               "framework:flutter.widgets.State.dispose",
	"activate":              "framework:flutter.widgets.State.activate",
	"deactivate":            "framework:flutter.widgets.State.deactivate",
	"reassemble":            "framework:flutter.widgets.State.reassemble",
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
	"addpostframecallback":  "framework:flutter.scheduler.SchedulerBinding.addPostFrameCallback",
	"findrenderobject":      "framework:flutter.widgets.BuildContext.findRenderObject",
	"createrenderobject":    "framework:flutter.rendering.RenderObjectWidget.createRenderObject",
	"updaterenderobject":    "framework:flutter.rendering.RenderObjectWidget.updateRenderObject",
	"keyedsubtree":          "framework:flutter.widgets.KeyedSubtree.new",
	"parentdatawidget":      "framework:flutter.widgets.ParentDataWidget.new",
	"slivergridparentdata":  "framework:flutter.rendering.SliverGridParentData.new",
	"didchangeapplifecyclestate":   "framework:flutter.widgets.WidgetsBindingObserver.didChangeAppLifecycleState",
	"didchangemetrics":             "framework:flutter.widgets.WidgetsBindingObserver.didChangeMetrics",
	"didchangelocales":             "framework:flutter.widgets.WidgetsBindingObserver.didChangeLocales",
	"didchangeplatformbrightness":  "framework:flutter.widgets.WidgetsBindingObserver.didChangePlatformBrightness",
	"didchangetextscalefactor":     "framework:flutter.widgets.WidgetsBindingObserver.didChangeTextScaleFactor",
	"didchangeaccessibilityfeatures": "framework:flutter.widgets.WidgetsBindingObserver.didChangeAccessibilityFeatures",
	"didpushroute":                 "framework:flutter.widgets.WidgetsBindingObserver.didPushRoute",
	"didpoproute":                  "framework:flutter.widgets.WidgetsBindingObserver.didPopRoute",
	"didpushrouteinformation":      "framework:flutter.widgets.WidgetsBindingObserver.didPushRouteInformation",
	"didrequestappexit":            "framework:flutter.widgets.WidgetsBindingObserver.didRequestAppExit",
	"didchangeviewfocus":           "framework:flutter.widgets.WidgetsBindingObserver.didChangeViewFocus",
	"handlestartbackgesture":       "framework:flutter.widgets.WidgetsBindingObserver.handleStartBackGesture",
	"handleupdatebackgestureprogress": "framework:flutter.widgets.WidgetsBindingObserver.handleUpdateBackGestureProgress",
	"handlecommitbackgesture":      "framework:flutter.widgets.WidgetsBindingObserver.handleCommitBackGesture",
	"handlecancelbackgesture":      "framework:flutter.widgets.WidgetsBindingObserver.handleCancelBackGesture",
	"didhavememorypressure":        "framework:flutter.widgets.WidgetsBindingObserver.didHaveMemoryPressure",
	"addobserver":                  "framework:flutter.widgets.WidgetsBinding.addObserver",
	"removeobserver":               "framework:flutter.widgets.WidgetsBinding.removeObserver",
	"addpersistentframecallback":   "framework:flutter.scheduler.SchedulerBinding.addPersistentFrameCallback",
	"addtimingscallback":           "framework:flutter.scheduler.SchedulerBinding.addTimingsCallback",
	"removetimingscallback":        "framework:flutter.scheduler.SchedulerBinding.removeTimingsCallback",
	"schedulewarmupframe":          "framework:flutter.scheduler.SchedulerBinding.scheduleWarmUpFrame",
	"ensurevisualupdate":           "framework:flutter.scheduler.SchedulerBinding.ensureVisualUpdate",
	"pushnamedandremoveuntil":      "framework:flutter.widgets.Navigator.pushNamedAndRemoveUntil",
	"pushreplacementnamed":         "framework:flutter.widgets.Navigator.pushReplacementNamed",
	"pushreplacement":              "framework:flutter.widgets.Navigator.pushReplacement",
	"pushnamed":                    "framework:flutter.widgets.Navigator.pushNamed",
	"pushandremoveuntil":           "framework:flutter.widgets.Navigator.pushAndRemoveUntil",
	"popandpushnamed":              "framework:flutter.widgets.Navigator.popAndPushNamed",
	"maybepop":                     "framework:flutter.widgets.Navigator.maybePop",
	"popuntil":                     "framework:flutter.widgets.Navigator.popUntil",
	"restorablepush":               "framework:flutter.widgets.Navigator.restorablePush",
	"restorablepushnamed":          "framework:flutter.widgets.Navigator.restorablePushNamed",
	"showsnackbar":                 "framework:flutter.material.ScaffoldMessengerState.showSnackBar",
	"hidecurrentsnackbar":          "framework:flutter.material.ScaffoldMessengerState.hideCurrentSnackBar",
	"removecurrentsnackbar":        "framework:flutter.material.ScaffoldMessengerState.removeCurrentSnackBar",

	// --- dart:core (stdlib:dart.core.*) ---
	"print":             "stdlib:dart.core.print",
	"tostring":          "stdlib:dart.core.toString",
	"hashcode":          "stdlib:dart.core.hashCode",
	"compareto":         "stdlib:dart.core.compareTo",
	"contains":          "stdlib:dart.core.contains",
	"containskey":       "stdlib:dart.core.Map.containsKey",
	"putifabsent":       "stdlib:dart.core.Map.putIfAbsent",
	"runtimetype":       "stdlib:dart.core.Object.runtimeType",
	"nosuchmethod":      "stdlib:dart.core.Object.noSuchMethod",
	"isempty":           "stdlib:dart.core.isEmpty",
	"isnotempty":        "stdlib:dart.core.isNotEmpty",
	"wheretype":         "stdlib:dart.core.Iterable.whereType",
	"expand":            "stdlib:dart.core.Iterable.expand",
	"fold":              "stdlib:dart.core.Iterable.fold",
	"reduce":            "stdlib:dart.core.Iterable.reduce",
	"firstwhere":        "stdlib:dart.core.Iterable.firstWhere",
	"singlewhere":       "stdlib:dart.core.Iterable.singleWhere",
	"map":               "stdlib:dart.core.map",
	"where":             "stdlib:dart.core.where",
	"join":              "stdlib:dart.core.String.join",
	"split":             "stdlib:dart.core.String.split",
	"substring":         "stdlib:dart.core.String.substring",
	"startswith":        "stdlib:dart.core.String.startsWith",
	"endswith":          "stdlib:dart.core.String.endsWith",
	"replaceall":        "stdlib:dart.core.String.replaceAll",
	"tolowercase":       "stdlib:dart.core.String.toLowerCase",
	"touppercase":       "stdlib:dart.core.String.toUpperCase",
	"removeat":          "stdlib:dart.core.List.removeAt",
	"removewhere":       "stdlib:dart.core.List.removeWhere",
	"addall":            "stdlib:dart.core.List.addAll",
	"putall":            "stdlib:dart.core.Map.addAll",
	"tolist":            "stdlib:dart.core.Iterable.toList",
	"toset":             "stdlib:dart.core.Iterable.toSet",
	"foreach":           "stdlib:dart.core.Iterable.forEach",
	"indexof":           "stdlib:dart.core.String.indexOf",
	"lastindexof":       "stdlib:dart.core.String.lastIndexOf",
	"trimleft":          "stdlib:dart.core.String.trimLeft",
	"trimright":         "stdlib:dart.core.String.trimRight",
	"trim":              "stdlib:dart.core.String.trim",
	"codeunitat":        "stdlib:dart.core.String.codeUnitAt",
	"matchendindex":     "stdlib:dart.core.Match.end",
	"add":               "stdlib:dart.core.List.add",
	"remove":            "stdlib:dart.core.List.remove",
	"clear":             "stdlib:dart.core.List.clear",
	"first":             "stdlib:dart.core.Iterable.first",
	"last":              "stdlib:dart.core.Iterable.last",
	"length":            "stdlib:dart.core.String.length",
	"parse":             "stdlib:dart.core.int.parse",
	"parsedouble":       "stdlib:dart.core.double.parse",
	"toradixstring":     "stdlib:dart.core.int.toRadixString",

	// --- dart:async (stdlib:dart.async.*) ---
	"then":              "stdlib:dart.async.Future.then",
	"catcherror":        "stdlib:dart.async.Future.catchError",
	"whencomplete":      "stdlib:dart.async.Future.whenComplete",
	"listen":            "stdlib:dart.async.Stream.listen",
	"cancel":            "stdlib:dart.async.StreamSubscription.cancel",
	"asstream":          "stdlib:dart.async.Future.asStream",
	"delayed":           "stdlib:dart.async.Future.delayed",
	"wait":              "stdlib:dart.async.Future.wait",
	"timeout":           "stdlib:dart.async.Future.timeout",
	"futurevalue":       "stdlib:dart.async.Future.value",
	"futureerror":       "stdlib:dart.async.Future.error",
	"futuresync":        "stdlib:dart.async.Future.sync",
	"futuremicrotask":   "stdlib:dart.async.Future.microtask",
	"completer":         "stdlib:dart.async.Completer.new",
	"complete":          "stdlib:dart.async.Completer.complete",
	"completeerror":     "stdlib:dart.async.Completer.completeError",
	"timer":             "stdlib:dart.async.Timer.new",
	"periodic":          "stdlib:dart.async.Timer.periodic",
	"schedulemicrotask": "stdlib:dart.async.scheduleMicrotask",
	"streamcontroller":  "stdlib:dart.async.StreamController.new",
	"transform":         "stdlib:dart.async.Stream.transform",
	"distinct":          "stdlib:dart.async.Stream.distinct",
	"takewhile":         "stdlib:dart.async.Stream.takeWhile",
	"skipwhile":         "stdlib:dart.async.Stream.skipWhile",
	"streamiterator":    "stdlib:dart.async.StreamIterator.new",

	// --- dart:io (stdlib:dart.io.*) ---
	"readasstring":         "stdlib:dart.io.File.readAsString",
	"writeasstring":        "stdlib:dart.io.File.writeAsString",
	"exists":               "stdlib:dart.io.File.exists",
	"supportsansiescapes":  "stdlib:dart.io.Stdout.supportsAnsiEscapes",
	"websocketimpl":        "stdlib:dart.io.WebSocketImpl.new",
	"nativesocket":         "stdlib:dart.io._NativeSocket.new",

	// --- dart:typed_data (stdlib:dart.typed_data.*) ---
	"float32x4list":   "stdlib:dart.typed_data.Float32x4List.new",
	"int64list":       "stdlib:dart.typed_data.Int64List.new",
	"offsetinbytes":   "stdlib:dart.typed_data.TypedData.offsetInBytes",
	"lengthinbytes":   "stdlib:dart.typed_data.TypedData.lengthInBytes",
	"elementsizeinbytes": "stdlib:dart.typed_data.TypedData.elementSizeInBytes",
	"setfloat32":      "stdlib:dart.typed_data.ByteData.setFloat32",
	"setfloat32x4":    "stdlib:dart.typed_data.ByteData.setFloat32x4",
	"setfloat64":      "stdlib:dart.typed_data.ByteData.setFloat64",
	"setfloat64x2":    "stdlib:dart.typed_data.ByteData.setFloat64x2",
	"setint8":         "stdlib:dart.typed_data.ByteData.setInt8",
	"setuint8":        "stdlib:dart.typed_data.ByteData.setUint8",
	"setint16":        "stdlib:dart.typed_data.ByteData.setInt16",
	"setuint16":       "stdlib:dart.typed_data.ByteData.setUint16",
	"setint32":        "stdlib:dart.typed_data.ByteData.setInt32",
	"setuint32":       "stdlib:dart.typed_data.ByteData.setUint32",
	"setint64":        "stdlib:dart.typed_data.ByteData.setInt64",
	"setuint64":       "stdlib:dart.typed_data.ByteData.setUint64",
	"getint8":         "stdlib:dart.typed_data.ByteData.getInt8",
	"getuint8":        "stdlib:dart.typed_data.ByteData.getUint8",
	"getint16":        "stdlib:dart.typed_data.ByteData.getInt16",
	"getuint16":       "stdlib:dart.typed_data.ByteData.getUint16",
	"getfloat32":      "stdlib:dart.typed_data.ByteData.getFloat32",
	"getfloat32x4":    "stdlib:dart.typed_data.ByteData.getFloat32x4",
	"getfloat64":      "stdlib:dart.typed_data.ByteData.getFloat64",
	"getfloat64x2":    "stdlib:dart.typed_data.ByteData.getFloat64x2",
	"getint32":        "stdlib:dart.typed_data.ByteData.getInt32",
	"getuint32":       "stdlib:dart.typed_data.ByteData.getUint32",
	"getint64":        "stdlib:dart.typed_data.ByteData.getInt64",
	"getuint64":       "stdlib:dart.typed_data.ByteData.getUint64",
	"unmodifiableuint8arrayview": "stdlib:dart.typed_data._UnmodifiableUint8ArrayView.new",
	"int32arrayview":  "stdlib:dart.typed_data._Int32ArrayView.new",

	// --- VM runtime (runtime:dart_vm.*) ---
	"new":                    "runtime:dart_vm.Closure.new",
	"invoke":                 "runtime:dart_vm.Function.invoke",
	"yieldstariterable":      "runtime:dart_vm.yieldStarIterable",
	"typeparameter":          "runtime:dart_vm.TypeParameter.new",
	"prependtypearguments":   "runtime:dart_vm.prependTypeArguments",
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
