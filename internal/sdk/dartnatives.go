package sdk

import "strings"

// VM native function names.
//
// Every Dart AOT snapshot carries the names of the VM natives its code
// can reach, as ordinary strings in the object pool: Ffi_dl_open,
// File_Open, Socket_CreateConnect, Isolate_spawnUri. They are the most
// reliable behavioural evidence a stripped binary offers -- they survive
// obfuscation, because the VM resolves them by name at runtime.
//
// Measured before this table existed: of 20 representative native names,
// the string heuristics classified 4, and one of those four was wrong
// (SecurityContext_UsePrivateKeyBytes read as "blockchain", because it
// contains "PrivateKey"). A stripped 3.9.2 sample carries 105 such names;
// a production app carries 1286.
//
// The classification is by NAMESPACE -- the part before the first
// underscore -- because that is how the SDK groups natives, and it is
// what carries the meaning: every File_* native is file I/O whichever one
// it is. Matching whole names would need all ~570 of them and would go
// stale on every SDK release; matching the namespace does not.
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

// dartNativeNamespaces maps a native's namespace to what reaching it
// means. Namespaces with no behavioural signal (Object_, Double_,
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

	// TLS. Distinct from "net": reaching these means the app terminates
	// or inspects TLS itself, which is where pinning and MITM live.
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

	// Observability. Interesting mainly because a release build that
	// still reaches these is unusual.
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

// DartNativeCategory classifies a VM native function name.
//
// The match is exact-then-namespace, never substring: a substring match
// is what turned SecurityContext_UsePrivateKeyBytes into a blockchain
// signal.
func DartNativeCategory(name string) (string, bool) {
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

// DartNativeNamespaces returns the namespaces this table classifies, for
// the SDK gate.
func DartNativeNamespaces() []string {
	out := make([]string, 0, len(dartNativeNamespaces))
	for ns := range dartNativeNamespaces {
		out = append(out, ns)
	}
	return out
}
