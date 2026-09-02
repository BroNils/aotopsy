package sdk

// Stub calling conventions.
//
// Dart AOT calls a handful of stubs with fixed register assignments
// declared as `struct <Name>ABI` in runtime/vm/constants_{arm64,x64}.h.
// Recovering what a stub call means requires knowing which register holds
// which operand, and the assignments differ per architecture -- the
// instance being type-tested is R0 on ARM64 and RAX on x86_64, but the
// destination type is R8 there and RBX here.
//
// Guessing these is how a probe reads the wrong register and reports a
// plausible value: DispatchTableNullErrorABI::kClassIdReg holds an
// integer class id, not a tagged pointer, so treating it as an object and
// loading a header from it yields whatever happens to sit at that address.
//
// Verified against 3.12.2 and re-derived per tag by
// TestRegisterABIMatchSDK.

// TypeTestABI is the calling convention for type testing stubs.
//
// Source: constants_arm64.h struct TypeTestABI, constants_x64.h likewise.
type TypeTestABI struct {
	InstanceReg                  int
	DstTypeReg                   int
	InstantiatorTypeArgumentsReg int
	FunctionTypeArgumentsReg     int
	SubtypeTestCacheReg          int
	ScratchReg                   int
	SubtypeTestCacheResultReg    int
}

// InstantiationABI is the calling convention for the
// InstantiateType/InstantiateTypeArguments stubs.
type InstantiationABI struct {
	UninstantiatedTypeArgumentsReg int
	InstantiatorTypeArgumentsReg   int
	FunctionTypeArgumentsReg       int
	ResultTypeArgumentsReg         int
	ResultTypeReg                  int
	ScratchReg                     int
}

// AssertSubtypeABI is the calling convention for AssertSubtypeStub.
type AssertSubtypeABI struct {
	SubTypeReg                   int
	SuperTypeReg                 int
	InstantiatorTypeArgumentsReg int
	FunctionTypeArgumentsReg     int
	DstNameReg                   int
}

var (
	arm64TypeTestABI = TypeTestABI{
		InstanceReg:                  0, // R0
		DstTypeReg:                   8, // R8
		InstantiatorTypeArgumentsReg: 2, // R2
		FunctionTypeArgumentsReg:     1, // R1
		SubtypeTestCacheReg:          3, // R3
		ScratchReg:                   4, // R4
		SubtypeTestCacheResultReg:    7, // R7
	}
	x86TypeTestABI = TypeTestABI{
		InstanceReg:                  0, // RAX
		DstTypeReg:                   3, // RBX
		InstantiatorTypeArgumentsReg: 2, // RDX
		FunctionTypeArgumentsReg:     1, // RCX
		SubtypeTestCacheReg:          9, // R9
		ScratchReg:                   6, // RSI
		SubtypeTestCacheResultReg:    8, // R8
	}

	arm64InstantiationABI = InstantiationABI{
		UninstantiatedTypeArgumentsReg: 3, // R3
		InstantiatorTypeArgumentsReg:   2, // R2
		FunctionTypeArgumentsReg:       1, // R1
		ResultTypeArgumentsReg:         0, // R0
		ResultTypeReg:                  0, // R0
		ScratchReg:                     8, // R8
	}
	x86InstantiationABI = InstantiationABI{
		UninstantiatedTypeArgumentsReg: 3, // RBX
		InstantiatorTypeArgumentsReg:   2, // RDX
		FunctionTypeArgumentsReg:       1, // RCX
		ResultTypeArgumentsReg:         0, // RAX
		ResultTypeReg:                  0, // RAX
		ScratchReg:                     9, // R9
	}

	arm64AssertSubtypeABI = AssertSubtypeABI{
		SubTypeReg:                   0, // R0
		SuperTypeReg:                 8, // R8
		InstantiatorTypeArgumentsReg: 2, // R2
		FunctionTypeArgumentsReg:     1, // R1
		DstNameReg:                   3, // R3
	}
	x86AssertSubtypeABI = AssertSubtypeABI{
		SubTypeReg:                   0, // RAX
		SuperTypeReg:                 3, // RBX
		InstantiatorTypeArgumentsReg: 2, // RDX
		FunctionTypeArgumentsReg:     1, // RCX
		DstNameReg:                   9, // R9
	}
)

// TypeTestRegNames maps each register a type-testing stub receives an
// operand in to a name for that operand, for the selected architecture.
//
// A type-testing stub is entered with its operands already in place, so
// none of these registers is ever written inside the stub. They are also
// not the ordinary Dart argument registers -- kInstanceReg is R0 on ARM64
// and RAX on x86_64, neither of which appears in
// DartCallingConvention::kCpuRegistersForArgs -- so nothing seeded them
// and every read printed the bare register. Measured over 1000 functions,
// that single omission was 511 of 794 leaked register tokens on ARM64
// (all of them x0, all inside TypeTestingStub_* functions) and 287 of 444
// on x86_64 (rax).
func TypeTestRegNames(isARM64 bool) map[string]string {
	abi := TypeTestRegs(isARM64)
	name := X86RegName
	if isARM64 {
		name = ARM64RegName
	}
	out := make(map[string]string, 7)
	for reg, role := range map[int]string{
		abi.InstanceReg:                  "instance",
		abi.DstTypeReg:                   "dstType",
		abi.InstantiatorTypeArgumentsReg: "instantiatorTypeArgs",
		abi.FunctionTypeArgumentsReg:     "functionTypeArgs",
		abi.SubtypeTestCacheReg:          "subtypeTestCache",
	} {
		if n := name(reg); n != "" {
			out[n] = role
		}
	}
	return out
}

// TypeTestRegs returns the type-testing stub ABI for an architecture.
func TypeTestRegs(isARM64 bool) TypeTestABI {
	if isARM64 {
		return arm64TypeTestABI
	}
	return x86TypeTestABI
}

// InstantiationRegs returns the instantiation stub ABI for an architecture.
func InstantiationRegs(isARM64 bool) InstantiationABI {
	if isARM64 {
		return arm64InstantiationABI
	}
	return x86InstantiationABI
}

// AssertSubtypeRegs returns the AssertSubtypeStub ABI for an architecture.
func AssertSubtypeRegs(isARM64 bool) AssertSubtypeABI {
	if isARM64 {
		return arm64AssertSubtypeABI
	}
	return x86AssertSubtypeABI
}

// ARM64ClassIdReg is DispatchTableNullErrorABI::kClassIdReg on ARM64 (R0).
//
// It holds a raw integer class id, not a tagged object pointer. A probe
// that dereferences it reads whatever lives at that address and reports
// it as a class -- the value looks like a small integer precisely because
// it is one.
const ARM64ClassIdReg = 0

// ClassIdRegName returns the register holding the receiver's class id at
// a dispatch-table call site, by architecture.
//
// The value is a plain integer class id, NOT a tagged object pointer.
// FlowGraphCompiler::EmitDispatchTableCall uses it as the table index:
//
//	ARM64   add LR, cid_reg, #offset ; call [DISPATCH_TABLE_REG + LR*8]
//	x86_64  call [table_reg + cid_reg*8 + offset]
//
// so anything that dereferences it is reading memory at an address equal
// to a small integer. ARM64 R0 also serves as the return register,
// FUNCTION_REG and kExceptionObjectReg; which role applies is positional,
// and at a dispatch-table call it is the class id.
func ClassIdRegName(isARM64 bool) string {
	if isARM64 {
		return "x0"
	}
	return "rcx"
}
