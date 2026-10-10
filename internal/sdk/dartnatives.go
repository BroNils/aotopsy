package sdk

import (
	_ "embed"
	"strings"
)

// VM native function names.
//
// Dart AOT snapshots can carry VM-native names as ordinary strings:
// Ffi_dl_open, File_Open, Socket_CreateConnect, Isolate_spawnUri. An exact
// name is reliable native-identity evidence and survives obfuscation because
// the VM resolves natives by name at runtime. Presence in snapshot inventory
// alone is not evidence that application code calls or reaches that native.
//
// Measured before this table existed: of 20 representative native names,
// the string heuristics classified 4, and one of those four was wrong
// (SecurityContext_UsePrivateKeyBytes read as "blockchain", because it
// contains "PrivateKey"). A stripped 3.9.2 sample carries 105 such names;
// a production app carries 1286.
//
// The semantic category is by NAMESPACE -- the part before the first
// underscore -- after exact SDK membership has been established. Every
// File_* native is a file-I/O native whichever member it is. The category
// describes the native capability, not proof of target behavior.
//
// Sources, both re-derived by TestDartNativeNamespacesMatchSDK:
//
//	runtime/vm/bootstrap_natives.h   BOOTSTRAP_NATIVE_LIST, BOOTSTRAP_FFI_NATIVE_LIST
//	runtime/bin/io_natives.cc        the dart:io natives

// Categories a native namespace can carry. These are the strings
// internal/signal uses, kept here so the table and the classifier cannot
// disagree about spelling.
const (
	NativeCatFFI         = "ffi"
	NativeCatDynamicLoad = "dynamic_load"
	NativeCatFile        = "file"
	NativeCatNet         = "net"
	NativeCatTLS         = "tls"
	NativeCatProcess     = "process"
	NativeCatIsolate     = "isolate"
	NativeCatEncryption  = "encryption"
	NativeCatDeviceInfo  = "device"
	NativeCatVMService   = "vm_service"
	NativeCatCompression = "compression"
)

// dartNativeNamespaces maps a native's namespace to the capability it
// represents. Namespaces with no useful security/reversing signal (Object_, Double_,
// Float32x4_, List_, String_ ...) are deliberately absent: they appear in
// every Dart program and classifying them would drown the interesting
// ones.
var dartNativeNamespaces = map[string]string{
	// dart:ffi -- the only way AOT code reaches native libraries.
	"Ffi": NativeCatFFI,

	// dart:io file system.
	"File":              NativeCatFile,
	"Directory":         NativeCatFile,
	"FileSystemWatcher": NativeCatFile,
	"Namespace":         NativeCatFile,

	// dart:io networking.
	"Socket":               NativeCatNet,
	"ServerSocket":         NativeCatNet,
	"SynchronousSocket":    NativeCatNet,
	"SocketBase":           NativeCatNet,
	"RawSocketOption":      NativeCatNet,
	"SocketControlMessage": NativeCatNet,
	"InternetAddress":      NativeCatNet,
	// Present through 2.x, gone by 3.12.2 -- kept so older binaries still
	// classify.
	"NetworkInterface":         NativeCatNet,
	"ResourceHandleImpl":       NativeCatNet,
	"SocketControlMessageImpl": NativeCatNet,

	// TLS. Distinct from "net" because these are TLS/context/certificate
	// primitives. Inventory membership still does not prove they are used.
	"SecureSocket":    NativeCatTLS,
	"SecurityContext": NativeCatTLS,
	"X509":            NativeCatTLS,

	"Process":     NativeCatProcess,
	"ProcessInfo": NativeCatProcess,

	// Isolates: the AOT equivalent of spawning code.
	//
	// The port namespaces were spelled *Impl through 2.19 and lost the
	// suffix in the 3.x cycle; both are kept, because a table that only
	// knows the current spelling silently stops classifying older
	// binaries.
	"Isolate":               NativeCatIsolate,
	"SendPort":              NativeCatIsolate,
	"SendPortImpl":          NativeCatIsolate,
	"RawReceivePort":        NativeCatIsolate,
	"RawReceivePortImpl":    NativeCatIsolate,
	"TransferableTypedData": NativeCatIsolate,

	"Crypto": NativeCatEncryption,

	"Platform": NativeCatDeviceInfo,

	// Observability-related native capabilities.
	"Developer": NativeCatVMService,
	"VMService": NativeCatVMService,
	"Timeline":  NativeCatVMService,

	"Filter": NativeCatCompression,
}

// dartNativeExact overrides the namespace category for individual
// natives whose meaning is narrower than their namespace.
var dartNativeExact = map[string]string{
	// Opening a shared library by name is dynamic loading, not just FFI.
	"Ffi_dl_open":                      NativeCatDynamicLoad,
	"Ffi_dl_close":                     NativeCatDynamicLoad,
	"Ffi_dl_lookup":                    NativeCatDynamicLoad,
	"Ffi_dl_getHandle":                 NativeCatDynamicLoad,
	"Ffi_dl_providesSymbol":            NativeCatDynamicLoad,
	"Ffi_GetFfiNativeResolver":         NativeCatDynamicLoad,
	"Ffi_createNativeCallableListener": NativeCatFFI,
}

// dartnatives_known.txt is the cross-version union of exact SDK natives whose
// namespaces this classifier intentionally assigns behavioral signal (plus any
// exact-name overrides). It is NOT the union of every mundane VM native:
// Object_*, Double_*, List_* and similar high-frequency namespaces are excluded
// deliberately. Namespace membership alone is not evidence that an arbitrary
// application string is a VM native: `Socket_NotARealNative` has the right
// prefix but the VM will never resolve it.
//
//go:embed dartnatives_known.txt
var dartNativeKnownText string

var dartNativeKnown = func() map[string]struct{} {
	lines := strings.Fields(dartNativeKnownText)
	out := make(map[string]struct{}, len(lines))
	for _, name := range lines {
		out[name] = struct{}{}
	}
	return out
}()

// DartNativeCategory classifies a VM native function name for an exact
// supported Dart version.
//
// The match is exact-then-namespace, never substring: a substring match
// is what turned SecurityContext_UsePrivateKeyBytes into a blockchain
// signal. The known-name file is a cross-version union, so version membership
// is checked separately: 123 of the 304 known names are not present in every
// supported SDK release.
func DartNativeCategory(dartVersion, name string) (string, bool) {
	if !dartNativeExistsAtVersion(dartVersion, name) {
		return "", false
	}
	if cat, ok := dartNativeExact[name]; ok {
		return cat, true
	}
	i := strings.IndexByte(name, '_')
	if i <= 0 || i == len(name)-1 {
		return "", false
	}
	// A native name is Namespace_memberName: the namespace is upper-camel
	// and the member starts lower-case or upper-case, but the whole thing
	// never contains a space or punctuation.
	ns := name[:i]
	cat, ok := dartNativeNamespaces[ns]
	return cat, ok
}

func dartNativeExistsAtVersion(dartVersion, name string) bool {
	if _, ok := dartNativeKnown[name]; !ok {
		return false
	}
	bit, ok := dartNativeVersionBit[dartVersion]
	if !ok {
		return false
	}
	if mask, varies := dartNativeVersionOverrides[name]; varies {
		return mask&bit != 0
	}
	return true
}

// DartNativeNamespaces returns the namespaces this table classifies, for
// the SDK gate.
func DartNativeNamespaces() []string {
	out := make([]string, 0, len(dartNativeNamespaces))
	for ns := range dartNativeNamespaces {
		out = append(out, ns)
	}
	return out
}
