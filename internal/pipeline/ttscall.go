package pipeline

import (
	"regexp"
	"strconv"

	"aotopsy/internal/cluster"
)

// Indirect calls that invoke a type-testing stub.
//
// dart-lang/sdk, verified at tag 3.12.2,
// runtime/vm/compiler/backend/flow_graph_compiler_x64.cc:
//
//	void FlowGraphCompiler::GenerateIndirectTTSCall(Assembler* assembler,
//	                                                Register reg_to_call,
//	                                                intptr_t sub_type_cache_index) {
//	  __ LoadWordFromPoolIndex(TypeTestABI::kSubtypeTestCacheReg,
//	                           sub_type_cache_index);
//	  __ Call(compiler::FieldAddress(
//	      reg_to_call,
//	      compiler::target::AbstractType::type_test_stub_entry_point_offset()));
//	}
//
// `reg_to_call` holds the AbstractType, so the callee is that type's testing
// stub -- the same stub named in typeteststubs.go.
//
// On the 3.12.2 x86_64 sample every one of the 1128 `CALL [reg+disp]` sites
// uses the SAME displacement, 0x7, because both shapes that reach an entry
// point through a field are at offset 8 with the heap tag subtracted:
// Code::entry_point_offset and AbstractType::type_test_stub_entry_point_offset.
// The displacement therefore says nothing about which of the two it is; only
// what the register holds does. Of those 1128:
//
//	405  the register came from a pool <vm:Code>   -- a VM stub, still unnamed
//	111  the register came from a pool Type        -- resolved here
//	491  the register came from an object field    -- a runtime type, so there
//	                                                  is no static answer
//	121  no provenance recovered
//
// Only the 111 are resolvable without inventing anything, and this handles
// exactly those.

// viaPoolIndex matches the provenance annotation the disassembler attaches to
// a register loaded from the object pool: "pp[123]" or "pp[123] <Type>".
var viaPoolIndex = regexp.MustCompile(`^pp\[(\d+)\]`)

// buildTTSCallTargets maps an object-pool INDEX to the type-testing stub name
// for the type in that slot, for slots that hold a Type at all. Returns nil
// when no type-testing stub names are available, so callers resolve nothing
// rather than guessing.
func buildTTSCallTargets(pool []cluster.PoolEntry, pl *PoolLookups) map[int]string {
	if pl == nil || len(pl.TypeTestingStubNames) == 0 {
		return nil
	}
	out := make(map[int]string)
	for _, pe := range pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		if name, ok := pl.TypeTestingStubNames[pe.RefID]; ok {
			out[pe.Index] = name
		}
	}
	return out
}

// ttsCallTarget returns the type-testing stub a call site invokes, given the
// provenance annotation of the called register, or "" when the site is not
// one of these.
func ttsCallTarget(via string, byPoolIndex map[int]string) string {
	if len(byPoolIndex) == 0 {
		return ""
	}
	m := viaPoolIndex.FindStringSubmatch(via)
	if m == nil {
		return ""
	}
	idx, err := strconv.Atoi(m[1])
	if err != nil {
		return ""
	}
	return byPoolIndex[idx]
}
