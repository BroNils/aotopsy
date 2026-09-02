package frida

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/decompiler"
	"aotopsy/internal/sdk"
)

// FridaHook is one function to generate an Interceptor.attach() block for.
type FridaHook struct {
	VA   uint64
	Name string
	// ArgRegs, if non-empty, is this function's REAL declared arity in
	// calling-convention order (from FuncIR.ArgRegIndices -- the
	// call-site-aggregation-inferred arity, see ARCHITECTURE.md's "Real
	// declared arity" section), so the generated hook dumps exactly
	// arg0..argN-1 matching the decompiled pseudocode signature instead
	// of the full raw x1-x7/rdi-r9 register set. Empty when arity wasn't
	// confidently resolved -- falls back to the full architecture default
	// (sdk.DartArgRegNames) rather than guessing.
	ArgRegs []string
}

// FridaProbe is a single instruction address to instrument directly
// (not a function entry) -- specifically, an unresolved indirect call
// site (`dynamicCall(indirectTarget_xN, ...)` in the decompiled
// pseudocode: a BLR/CALL reg whose target static analysis could not
// name). Frida CAN resolve what static analysis couldn't: attaching at
// the exact call instruction's address and reading the target register
// out of this.context reveals the real runtime target, which the user
// can then cross-reference against aotopsy's own VA numbering (the
// script computes and logs the module-relative offset for exactly this
// purpose -- paste it into `--func`/`--find` to identify it).
//
// This does NOT distinguish "genuinely unresolved in the pseudocode"
// from "resolved via a runtime-tracked sentinel elsewhere in this same
// call chain" (e.g. a THR-cached stub call) -- see ir.go's collection
// site for why that distinction isn't cheaply available here. Probing
// an already-named call site is harmless (it just confirms the
// resolution dynamically) so this deliberately errs toward including
// too much rather than silently missing a real gap.
type FridaProbe struct {
	VA       uint64
	Reg      string
	FuncName string
}

// GenerateFridaScript emits a ready-to-run Frida script (see
// https://frida.re/docs/javascript-api/) that hooks every given VA with
// Interceptor.attach(), dumping incoming argument registers and the
// return value, PLUS a second set of raw instruction-address probes for
// unresolved indirect call sites (see FridaProbe's doc comment). VAs are
// module-relative offsets (see decompile_native_cmd.go's symbolNames --
// these are the same VA numbers resolved from the snapshot's own
// instructions-table layout, which is the ELF's own declared virtual
// address, i.e. already a module-relative offset for a PIE .so -- no
// extra load-bias adjustment is needed here).
//
// SAFETY: this generator does NOT know anything about a specific target
// app's own attach requirements or anti-tamper defenses -- it emits a
// standalone, generically-loadable script. Two real, confirmed hazards
// found analyzing a real hardened app with a broadly similar
// architecture (Dart AOT + native anti-tamper), documented in this
// project's own history (see the caller-side comment this generates
// into the script header, and the project's `knowledge/30_*.md` for the
// full incident writeups) apply generically to ANY sufficiently
// hardened target, not just that one app:
//  1. Interceptor.attach directly on (or even just NEAR) an indirect
//     CALL/BLR site inside tightly-packed, hot AOT-compiled machine code
//     can corrupt nearby control flow when Frida's trampoline patch
//     doesn't have enough room -- confirmed via a clean A/B test to
//     cause a reproducible SIGSEGV on a real app, including on a plain
//     MOV several instructions before the actual risky CALL, not only
//     on the CALL itself. The probes this generator emits use
//     Interceptor.attach (the simple, broadly-compatible default), NOT
//     the safer but far more involved hardware-breakpoint alternative
//     (Thread#setHardwareBreakpoint, which patches zero code bytes) --
//     that alternative needs per-target-app cooperation (a shared
//     Process.setExceptionHandler dispatch, since only one handler can
//     be installed process-wide, plus per-thread arming/disarming) that
//     can't be assumed generically for an arbitrary target. If a probe
//     crashes the target, don't just retry it -- convert it to a
//     hardware breakpoint by hand (a real, working reference
//     implementation exists in this repo's own history if you have
//     access to it) rather than assuming it's a fluke.
//  2. Spawning (`-f`) a hardened app and attaching immediately can hit a
//     cold-start detection window some apps specifically watch for
//     (confirmed on the same real app: a short post-spawn age check
//     before attaching was necessary to reliably survive). Attaching to
//     an already-running, already-"aged" process is the safer default
//     for such targets, not spawn+resume.
//
// Neither hazard is unique to Dart/Flutter -- both are properties of
// Frida's own instrumentation mechanisms interacting with hardened
// native code, so treat them as a checklist for ANY sufficiently
// defended target, not something to ignore just because THIS particular
// app hasn't been fingerprinted as hardened yet.
// FridaOptions carries the opt-in extras a caller can request on top of the
// hooks/probes. They are OFF by default because each one costs real runtime
// overhead on the target.
type FridaOptions struct {
	// Stalker emits Stalker.follow() for every non-VM-internal thread,
	// reporting a per-target call summary. Enabled by --gen-frida-stalker.
	Stalker bool
	// StalkerMinCalls suppresses targets seen fewer than this many times in
	// one summary window (0 = report everything).
	StalkerMinCalls int
}

func GenerateFridaScriptWithOptions(libPath string, isARM64 bool, hooks []FridaHook, probes []FridaProbe, opts FridaOptions) string {
	moduleName := filepath.Base(libPath)
	defaultRegs := sdk.DartArgRegNames(isARM64)

	var b strings.Builder
	fmt.Fprintf(&b, "// Auto-generated by aotopsy decompile-native --gen-frida\n")
	fmt.Fprintf(&b, "// Target module: %s (%s)\n", moduleName, archLabel(isARM64))
	fmt.Fprintf(&b, "// %d function hook(s), %d indirect-call probe(s).\n", len(hooks), len(probes))
	fmt.Fprintf(&b, "// Attach with: frida -U -f <package> -l <this file> --no-pause\n")
	fmt.Fprintf(&b, "// or: frida -U <package> -l <this file>\n")
	fmt.Fprintf(&b, "//\n")
	fmt.Fprintf(&b, "// SAFETY (read before running against a hardened/anti-tamper target):\n")
	fmt.Fprintf(&b, "// - Prefer attaching to an already-running process over spawning (-f) it --\n")
	fmt.Fprintf(&b, "//   some apps specifically watch for a spawn+immediate-attach pattern.\n")
	if len(probes) > 0 {
		fmt.Fprintf(&b, "// - This script includes %d indirect-call-site PROBE(s) below. Interceptor.attach\n", len(probes))
		fmt.Fprintf(&b, "//   near a tight indirect-call site in hot compiled code has caused a confirmed,\n")
		fmt.Fprintf(&b, "//   reproducible crash on at least one real hardened app -- test cautiously\n")
		fmt.Fprintf(&b, "//   (non-critical build/account first), and if the target dies right as a\n")
		fmt.Fprintf(&b, "//   probe would fire, don't just retry: that's very likely this exact hazard,\n")
		fmt.Fprintf(&b, "//   not a fluke. See generateFridaScript's doc comment in generator.go.\n")
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "const MODULE_NAME = %q;\n", moduleName)
	fmt.Fprintf(&b, "const DEFAULT_REGS = %s;\n\n", jsStringArray(defaultRegs))
	b.WriteString(`function dumpArgs(ctx, regs) {
  const out = {};
  for (const r of regs) {
    if (ctx[r] !== undefined) out[r] = ctx[r].toString();
  }
  return out;
}

function hex(np) {
  try { return np.toString(); } catch (e) { return String(np); }
}

`)
	fmt.Fprintf(&b, "const base = Process.getModuleByName(MODULE_NAME).base;\n\n")

	b.WriteString("const hooks = [\n")
	for _, h := range hooks {
		if len(h.ArgRegs) > 0 {
			fmt.Fprintf(&b, "  { va: 0x%x, name: %q, regs: %s },\n", h.VA, h.Name, jsStringArray(h.ArgRegs))
		} else {
			fmt.Fprintf(&b, "  { va: 0x%x, name: %q, regs: null },\n", h.VA, h.Name)
		}
	}
	b.WriteString("];\n\n")
	b.WriteString(`hooks.forEach(function (h) {
  const target = base.add(h.va);
  const regs = h.regs || DEFAULT_REGS;
  try {
    Interceptor.attach(target, {
      onEnter(args) {
        console.log("[aotopsy] -> " + h.name + " @ " + hex(target) + " args=" + JSON.stringify(dumpArgs(this.context, regs)));
      },
      onLeave(retval) {
        console.log("[aotopsy] <- " + h.name + " retval=" + hex(retval));
      },
    });
  } catch (e) {
    console.log("[aotopsy] failed to hook " + h.name + " @ " + hex(target) + ": " + e);
  }
});

console.log("[aotopsy] " + hooks.length + " function hook(s) installed on " + MODULE_NAME);
`)

	if len(probes) > 0 {
		b.WriteString("\n// Indirect-call-site probes: reads the target register at the exact\n")
		b.WriteString("// BLR/CALL instruction static analysis couldn't resolve, logging the\n")
		b.WriteString("// runtime target's module-relative offset -- paste that hex offset into\n")
		b.WriteString("// `aotopsy _debug decompile-native --func <offset>`/`--find` to identify it.\n")
		b.WriteString("const probes = [\n")
		for _, p := range probes {
			fmt.Fprintf(&b, "  { va: 0x%x, reg: %q, func: %q },\n", p.VA, p.Reg, p.FuncName)
		}
		b.WriteString("];\n\n")
		b.WriteString(`probes.forEach(function (p) {
  const target = base.add(p.va);
  try {
    Interceptor.attach(target, {
      onEnter() {
        const val = this.context[p.reg];
        if (val === undefined) {
          console.log("[aotopsy] probe " + p.func + " @ " + hex(target) + ": register " + p.reg + " not available in this.context");
          return;
        }
        const resolved = val.sub(base);
        console.log("[aotopsy] probe " + p.func + " @ " + hex(target) + ": " + p.reg + "=" + hex(val) + " (module+0x" + resolved.toString(16) + ")");
      },
    });
  } catch (e) {
    console.log("[aotopsy] failed to install probe for " + p.func + " @ " + hex(target) + ": " + e);
  }
});

console.log("[aotopsy] " + probes.length + " indirect-call probe(s) installed on " + MODULE_NAME);
`)
	}

	// Stalker call tracing. Emitted only when the caller asked for it
	// (--gen-frida-stalker): Stalker rewrites and re-executes every basic
	// block of every followed thread, which is far too invasive to ship
	// switched on next to the ordinary hooks.
	//
	// An earlier revision emitted this unconditionally behind a
	// `var ENABLE_STALKER = false;` that nothing could flip, together with a
	// `MemoryAccessMonitor.enable([0, 0x1000], ...)` block. That second block
	// was removed rather than wired up: MemoryAccessMonitor takes an array of
	// {base, size} ranges (so `[0, 0x1000]` would throw), it is page-granular,
	// and the Thread structure it claimed to watch is touched by essentially
	// every generated instruction -- there is no useful signal to be had from
	// it, at any range.
	if opts.Stalker {
		fmt.Fprintf(&b, `
// === Stalker: per-thread call tracing (--gen-frida-stalker) ===
// Follows every thread whose name does not look like a Dart VM helper
// (GC sweeper / background compiler / Stalker's own worker), and prints a
// periodic summary of call targets. Overhead is significant -- this is a
// deliberate, opt-in trade.
var STALKER_MIN_CALLS = %d;

function stalkerSkipThread(name) {
  // Dart VM internal threads: "DartWorker", "Dart Profiler",
  // "dart:io EventHandler", plus generic GC/Compiler helpers.
  return /^(DartWorker|Dart Profiler|dart:io|gum-js-loop)/.test(name) ||
         name.indexOf("GC") >= 0 || name.indexOf("Compiler") >= 0;
}

Process.enumerateThreads().forEach(function (thread) {
  var name = thread.name || ("tid-" + thread.id);
  if (stalkerSkipThread(name)) {
    console.log("[aotopsy] stalker: skipping " + name + " (tid=" + thread.id + ")");
    return;
  }
  Stalker.follow(thread.id, {
    events: { call: true, ret: false, exec: false, block: false },
    onCallSummary: function (summary) {
      Object.keys(summary).forEach(function (target) {
        var count = summary[target];
        if (count < STALKER_MIN_CALLS) return;
        var addr = ptr(target);
        var mod = Process.findModuleByAddress(addr);
        var label = mod
          ? mod.name + "+0x" + addr.sub(mod.base).toString(16)
          : hex(addr);
        console.log("[aotopsy] stalker " + name + ": " + label + " x" + count);
      });
    }
  });
  console.log("[aotopsy] stalker: following " + name + " (tid=" + thread.id + ")");
});
`, opts.StalkerMinCalls)
	}
	return b.String()
}

// WriteFridaScript renders hooks/probes and writes them to outPath, or
// to <outDir>/hooks.js if outPath is empty. No-ops with a warning (not
// an error) if there's nothing to hook, since --gen-frida alongside
// --max 0 hits or a fully framework-excluded run is a legitimate, if
// uninteresting, result.
func WriteFridaScript(outPath, outDir, libPath string, isARM64 bool, hooks []FridaHook, probes []FridaProbe, opts FridaOptions) error {
	if len(hooks) == 0 && len(probes) == 0 {
		fmt.Fprintln(os.Stderr, "--gen-frida: no functions were decompiled, nothing to hook -- skipping script generation")
		return nil
	}
	if outPath == "" {
		outPath = filepath.Join(outDir, "hooks.js")
	}
	script := GenerateFridaScriptWithOptions(libPath, isARM64, hooks, probes, opts)
	if err := os.WriteFile(outPath, []byte(script), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "Frida script (%d function hooks, %d indirect-call probes) written to %s\n", len(hooks), len(probes), outPath)
	return nil
}

func archLabel(isARM64 bool) string {
	if isARM64 {
		return "arm64"
	}
	return "x86_64"
}

func jsStringArray(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// MaxFridaProbes caps the number of indirect-call-site probes emitted in
// one script -- a large --all/--from-main run can have thousands of
// indirect call sites, and attaching that many Interceptor hooks is both
// slow to install and floods the console with output. Not a silent
// truncation: callers log how many were dropped.
const MaxFridaProbes = 300

// RealArgRegs returns fir's real declared arity (FuncIR.ArgRegIndices),
// mapped to register names in calling-convention order, or nil if arity
// wasn't confidently resolved -- callers fall back to the full
// architecture-default register set (see FridaHook.ArgRegs's doc
// comment) rather than guessing.
func RealArgRegs(fir *decompiler.FuncIR) []string {
	if len(fir.ArgRegIndices) == 0 {
		return nil
	}
	regs := make([]string, 0, len(fir.ArgRegIndices))
	for _, idx := range fir.ArgRegIndices {
		if idx < 0 || idx >= len(fir.ArgRegs) {
			return nil
		}
		regs = append(regs, fir.ArgRegs[idx])
	}
	return regs
}

// CollectIndirectCallProbes walks fir's blocks for OpCall instructions
// whose Target is a bare register (an unresolved indirect call site --
// see FridaProbe's doc comment), skipping memory-operand targets like
// x86_64's direct "[r14+off]" THR-cached-call shape (already fully
// resolved by internal/vmtables.ThreadStubOffsets, nothing dynamic to
// learn) and any target that's already a resolved "0x..." VA.
func CollectIndirectCallProbes(fir *decompiler.FuncIR) []FridaProbe {
	var out []FridaProbe
	for _, blk := range fir.Blocks {
		for _, ins := range blk.Instrs {
			if ins.Op != decompiler.OpCall || ins.Target == "" {
				continue
			}
			// H-6 fix: was `strings.Contains(ins.Target, "[")` which skips ALL
			// bracket-containing targets including bare register dereferences
			// like `[rax]`. Only skip memory operands with offsets: `[reg+offset]`.
			if strings.HasPrefix(ins.Target, "0x") || (strings.Contains(ins.Target, "[") && strings.Contains(ins.Target, "+")) {
				continue
			}
			out = append(out, FridaProbe{VA: ins.Addr, Reg: ins.Target, FuncName: fir.Name})
		}
	}
	return out
}
