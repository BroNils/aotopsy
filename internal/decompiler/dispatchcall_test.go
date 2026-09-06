package decompiler

import (
	"testing"

	"aotopsy/internal/sdk"
)

func dispatchFIR(linkReg string, srcs []struct {
	src, target string
	call        bool
}) *FuncIR {
	fir := &FuncIR{LinkReg: linkReg, ArgRegs: []string{"a"}}
	var ins []Instr
	for _, s := range srcs {
		i := Instr{Src: s.src, Target: s.target}
		if s.call {
			i.Op = OpCall
		}
		ins = append(ins, i)
	}
	fir.Blocks = []Block{{ID: 0, StartVA: 0x1000, Instrs: ins}}
	return fir
}

// TestARM64DispatchCallRecovery: `Call(Address(DISPATCH_TABLE_REG, LR, UXTX,
// Scaled))` assembles to a load through x21 followed by `blr x30`, with the
// selector in the `add`/`sub` that set LR.
func TestARM64DispatchCallRecovery(t *testing.T) {
	origin := sdk.DispatchTableOriginElement(true)

	t.Run("add form", func(t *testing.T) {
		fir := dispatchFIR("x30", []struct {
			src, target string
			call        bool
		}{
			{"add x30, x0, #0x40", "", false},
			{"ldr x30, [x21,x30,lsl #3]", "", false},
			{"blr x30", "x30", true},
		})
		annotateDispatchCalls(fir)
		got := fir.Blocks[0].Instrs[2]
		if !got.IsDispatchCall {
			t.Fatal("not recognised as a dispatch call")
		}
		if want := 0x40 + origin; got.DispatchSelector != want {
			t.Errorf("selector = %d, want %d", got.DispatchSelector, want)
		}
	})

	// kOriginElement exists so a selector BELOW the origin is reachable with a
	// `sub`; getting the sign wrong would silently mislabel every one of them.
	t.Run("sub form", func(t *testing.T) {
		fir := dispatchFIR("x30", []struct {
			src, target string
			call        bool
		}{
			{"sub x30, x0, #0x10", "", false},
			{"ldr x30, [x21,x30,lsl #3]", "", false},
			{"blr x30", "x30", true},
		})
		annotateDispatchCalls(fir)
		if want := origin - 0x10; fir.Blocks[0].Instrs[2].DispatchSelector != want {
			t.Errorf("selector = %d, want %d", fir.Blocks[0].Instrs[2].DispatchSelector, want)
		}
	})

	// A `blr x30` with no dispatch-table load is a different call kind
	// entirely -- an entry-point load, for one -- and must not be claimed.
	t.Run("blr x30 without the dispatch load", func(t *testing.T) {
		fir := dispatchFIR("x30", []struct {
			src, target string
			call        bool
		}{
			{"ldur x30, [x30,#7]", "", false},
			{"blr x30", "x30", true},
		})
		annotateDispatchCalls(fir)
		if fir.Blocks[0].Instrs[1].IsDispatchCall {
			t.Error("an entry-point-load call was claimed as a dispatch call")
		}
	})

	// The load identifies the call even when the offset is not recoverable;
	// reporting the call without a selector beats reporting neither.
	t.Run("load without a recoverable offset", func(t *testing.T) {
		fir := dispatchFIR("x30", []struct {
			src, target string
			call        bool
		}{
			{"ldr x30, [x21,x30,lsl #3]", "", false},
			{"blr x30", "x30", true},
		})
		annotateDispatchCalls(fir)
		got := fir.Blocks[0].Instrs[1]
		if !got.IsDispatchCall {
			t.Fatal("not recognised without the add")
		}
		if got.DispatchSelector != dispatchSelectorUnknown {
			t.Errorf("selector = %d, want unknown", got.DispatchSelector)
		}
	})
}

// TestX64DispatchCallRecovery: `call [RAX + cid*8 + offset]` with
// offset = (selector - kOriginElement) * kWordSize.
func TestX64DispatchCallRecovery(t *testing.T) {
	origin := sdk.DispatchTableOriginElement(false)
	for _, tc := range []struct {
		target string
		want   int
	}{
		{"[rax+8*rcx+0x200a8]", 0x200a8/8 + origin},
		{"[rax+8*rcx]", origin},
	} {
		fir := dispatchFIR("", []struct {
			src, target string
			call        bool
		}{{"call " + tc.target, tc.target, true}})
		annotateDispatchCalls(fir)
		got := fir.Blocks[0].Instrs[0]
		if !got.IsDispatchCall {
			t.Errorf("%s: not recognised", tc.target)
			continue
		}
		if got.DispatchSelector != tc.want {
			t.Errorf("%s: selector = %d, want %d", tc.target, got.DispatchSelector, tc.want)
		}
	}

	// An ordinary indirect call must not be claimed.
	for _, target := range []string{"rcx", "[r11+0x7]", "[r14+0x240]"} {
		fir := dispatchFIR("", []struct {
			src, target string
			call        bool
		}{{"call " + target, target, true}})
		annotateDispatchCalls(fir)
		if fir.Blocks[0].Instrs[0].IsDispatchCall {
			t.Errorf("%s claimed as a dispatch call", target)
		}
	}
}
