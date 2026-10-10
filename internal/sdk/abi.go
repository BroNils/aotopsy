package sdk

import "aotopsy/internal/snapshot"

const AbsentRegister = -1

type TypeTestABI struct {
	InstanceReg                  int
	DstTypeReg                   int
	InstantiatorTypeArgumentsReg int
	FunctionTypeArgumentsReg     int
	SubtypeTestCacheReg          int
	ScratchReg                   int
	ResultReg                    int
	SubtypeTestCacheResultReg    int
}

type InstantiationABI struct {
	UninstantiatedTypeArgumentsReg int
	InstantiatorTypeArgumentsReg   int
	FunctionTypeArgumentsReg       int
	ResultTypeArgumentsReg         int
	ResultTypeReg                  int
	ScratchReg                     int
}

type AssertSubtypeABI struct {
	SubTypeReg                   int
	SuperTypeReg                 int
	InstantiatorTypeArgumentsReg int
	FunctionTypeArgumentsReg     int
	DstNameReg                   int
}

type AllocateObjectABI struct {
	ResultReg        int
	TypeArgumentsReg int
	TagsReg          int
}

type SuspendStubABI struct {
	ArgumentReg int
	TypeArgsReg int
}

type DispatchTableNullErrorABI struct {
	ClassIDReg int
}

func TypeTestRegs(dartVersion string, isARM64 bool) (TypeTestABI, bool) {
	if !isSupportedDartVersion(dartVersion) {
		return TypeTestABI{}, false
	}
	abi := TypeTestABI{ResultReg: AbsentRegister, SubtypeTestCacheResultReg: AbsentRegister}
	if isARM64 {
		abi.InstanceReg, abi.DstTypeReg = 0, 8
		abi.InstantiatorTypeArgumentsReg, abi.FunctionTypeArgumentsReg = 2, 1
		abi.SubtypeTestCacheReg, abi.ScratchReg = 3, 4
		if dartVersion == "2.10.0" {
			abi.ResultReg = 0
		} else {
			abi.SubtypeTestCacheResultReg = 7
		}
		return abi, true
	}
	abi.InstanceReg, abi.DstTypeReg = 0, 3
	abi.InstantiatorTypeArgumentsReg, abi.FunctionTypeArgumentsReg = 2, 1
	abi.SubtypeTestCacheReg, abi.ScratchReg = 9, 6
	if dartVersion == "2.10.0" {
		abi.ResultReg = 0
	} else {
		abi.SubtypeTestCacheResultReg = 8
	}
	return abi, true
}

func InstantiationRegs(dartVersion string, isARM64 bool) (InstantiationABI, bool) {
	if !isSupportedDartVersion(dartVersion) {
		return InstantiationABI{}, false
	}
	abi := InstantiationABI{ScratchReg: AbsentRegister}
	if isARM64 {
		abi.UninstantiatedTypeArgumentsReg, abi.InstantiatorTypeArgumentsReg = 3, 2
		abi.FunctionTypeArgumentsReg, abi.ResultTypeArgumentsReg, abi.ResultTypeReg = 1, 0, 0
		if snapshot.VersionAtLeast(dartVersion, "2.18.0") {
			abi.ScratchReg = 8
		}
		return abi, true
	}
	abi.UninstantiatedTypeArgumentsReg, abi.InstantiatorTypeArgumentsReg = 3, 2
	abi.FunctionTypeArgumentsReg, abi.ResultTypeArgumentsReg, abi.ResultTypeReg = 1, 0, 0
	if snapshot.VersionAtLeast(dartVersion, "2.18.0") {
		abi.ScratchReg = 9
	}
	return abi, true
}

func AssertSubtypeRegs(dartVersion string, isARM64 bool) (AssertSubtypeABI, bool) {
	if !isSupportedDartVersion(dartVersion) || dartVersion == "2.10.0" {
		return AssertSubtypeABI{}, false
	}
	if isARM64 {
		return AssertSubtypeABI{SubTypeReg: 0, SuperTypeReg: 8, InstantiatorTypeArgumentsReg: 2, FunctionTypeArgumentsReg: 1, DstNameReg: 3}, true
	}
	return AssertSubtypeABI{SubTypeReg: 0, SuperTypeReg: 3, InstantiatorTypeArgumentsReg: 2, FunctionTypeArgumentsReg: 1, DstNameReg: 9}, true
}

func AllocateObjectRegs(dartVersion string, isARM64 bool) (AllocateObjectABI, bool) {
	if !isSupportedDartVersion(dartVersion) {
		return AllocateObjectABI{}, false
	}
	abi := AllocateObjectABI{TagsReg: AbsentRegister}
	if isARM64 {
		abi.ResultReg, abi.TypeArgumentsReg = 0, 1
		if snapshot.VersionAtLeast(dartVersion, "2.17.6") {
			abi.TagsReg = 2
		}
		return abi, true
	}
	abi.ResultReg, abi.TypeArgumentsReg = 0, 2
	if snapshot.VersionAtLeast(dartVersion, "2.17.6") {
		abi.TagsReg = 8
	}
	return abi, true
}

func SuspendStubRegs(dartVersion string, isARM64 bool) (SuspendStubABI, bool) {
	if !isSupportedDartVersion(dartVersion) || !snapshot.VersionAtLeast(dartVersion, "2.18.0") {
		return SuspendStubABI{}, false
	}
	abi := SuspendStubABI{TypeArgsReg: AbsentRegister}
	if isARM64 {
		abi.ArgumentReg = 0
		if snapshot.VersionAtLeast(dartVersion, "3.0.5") {
			abi.TypeArgsReg = 1
		}
		return abi, true
	}
	abi.ArgumentReg = 0
	if snapshot.VersionAtLeast(dartVersion, "3.0.5") {
		abi.TypeArgsReg = 2
	}
	return abi, true
}

func DispatchTableNullErrorRegs(dartVersion string, isARM64 bool) (DispatchTableNullErrorABI, bool) {
	if !isSupportedDartVersion(dartVersion) || !snapshot.VersionAtLeast(dartVersion, "2.13.0") {
		return DispatchTableNullErrorABI{}, false
	}
	if isARM64 {
		return DispatchTableNullErrorABI{ClassIDReg: 0}, true
	}
	return DispatchTableNullErrorABI{ClassIDReg: 1}, true
}

// DispatchTableClassIDReg returns the class-id index register for an actual
// dispatch-table call when the SDK fixes that register in an ABI. Dart 2.10 and
// 2.12 pass an arbitrary cid_reg into EmitDispatchTableCall, so no single global
// register is correct for those releases. Dart 2.13+ routes the call through
// DispatchTableNullErrorABI::kClassIdReg and therefore has a fixed register.
func DispatchTableClassIDReg(dartVersion string, isARM64 bool) (int, bool) {
	if _, ok := DispatchTableOriginElement(dartVersion, isARM64); !ok {
		return 0, false
	}
	abi, ok := DispatchTableNullErrorRegs(dartVersion, isARM64)
	if !ok {
		return 0, false
	}
	return abi.ClassIDReg, true
}

// IsDispatchTableClassIDReg reports whether reg can be the class-id register
// at a dispatch-table call in this exact SDK. This is deliberately different
// from DispatchTableClassIDReg: Dart 2.10/2.12 pass cid_reg as an arbitrary
// Register parameter, so there is no single ABI register to return, but an
// observed call-site index register is still valid evidence. From 2.13 onward
// the SDK fixes the register through DispatchTableNullErrorABI.
func IsDispatchTableClassIDReg(dartVersion string, isARM64 bool, reg int) bool {
	if !isSupportedDartVersion(dartVersion) {
		return false
	}
	if fixed, ok := DispatchTableClassIDReg(dartVersion, isARM64); ok {
		return reg == fixed
	}
	if dartVersion != "2.10.0" && dartVersion != "2.12.0" {
		return false
	}
	if isARM64 {
		return reg >= 0 && reg <= 30
	}
	return reg >= 0 && reg < 16
}

// IsARM64DispatchTableIndexReg reports whether reg can hold the computed GDT
// slot index at the load from DISPATCH_TABLE_REG. Dart 2.10/2.12 update the
// caller-selected cid_reg in place. From 2.13 onward the compiler computes the
// index in LR (R30) from the fixed class-id register.
func IsARM64DispatchTableIndexReg(dartVersion string, reg int) bool {
	if !isSupportedDartVersion(dartVersion) || reg < 0 || reg > 30 {
		return false
	}
	if dartVersion == "2.10.0" || dartVersion == "2.12.0" {
		return true
	}
	return reg == ARM64LinkReg
}

// IsARM64DispatchTableIndexComputation reports whether dst = src +/- offset is
// the register shape emitted by EmitDispatchTableCall for this exact SDK.
// Legacy releases mutate the arbitrary cid_reg in place; 2.13+ use LR as the
// destination and DispatchTableNullErrorABI::kClassIdReg (R0) as the source.
func IsARM64DispatchTableIndexComputation(dartVersion string, dstReg, srcReg int) bool {
	if !IsARM64DispatchTableIndexReg(dartVersion, dstReg) {
		return false
	}
	if dartVersion == "2.10.0" || dartVersion == "2.12.0" {
		return dstReg == srcReg
	}
	classReg, ok := DispatchTableClassIDReg(dartVersion, ArchARM64)
	return ok && dstReg == ARM64LinkReg && srcReg == classReg
}

func ClassIdRegName(dartVersion string, isARM64 bool) (string, bool) {
	reg, ok := DispatchTableClassIDReg(dartVersion, isARM64)
	if !ok {
		return "", false
	}
	if isARM64 {
		return ARM64RegName(reg), true
	}
	return X86RegName(reg), true
}

func TypeTestRegNames(dartVersion string, isARM64 bool) map[string]string {
	abi, ok := TypeTestRegs(dartVersion, isARM64)
	if !ok {
		return nil
	}
	name := X86RegName
	if isARM64 {
		name = ARM64RegName
	}
	out := make(map[string]string, 5)
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
