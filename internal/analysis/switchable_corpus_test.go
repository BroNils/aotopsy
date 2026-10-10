package analysis

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/samplecorpus"
)

var plainArm64Sample = regexp.MustCompile(`^dart-\d+\.\d+\.\d+-arm64\.so$`)

// Every switchable call site loads its UnlinkedCall into R5 and the stub into
// LR with one LDP (EmitInstanceCallAOT). Its receiver is read from
// [SP + (SizeWithoutTypeArgs-1)*8] and the UnlinkedCall's args_descriptor holds
// the same count, so the two independent encodings of the argument count must
// agree. This is the corpus-wide proof of the receiver rule decompiler/
// switchable.go relies on, and of cluster.ArgsDescriptorDecoder (cached
// descriptors on <= 3.12.2, snapshot Arrays of Smis on 3.13.0).
func TestSwitchableReceiverSlotMatchesArgumentsDescriptor(t *testing.T) {
	ran := 0
	for _, name := range samplecorpus.ExpectedFiles() {
		if !plainArm64Sample.MatchString(name) {
			continue
		}
		path, err := samplecorpus.RequireSample(name)
		if errors.Is(err, samplecorpus.ErrNoCorpus) {
			t.Skip("no sample corpus")
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sc, err := LoadSnapshot(path, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		version := sc.Info.Version.DartVersion
		poolRef := map[int]int{}
		for _, pe := range sc.Result.Pool {
			if pe.Kind == cluster.PoolTagged {
				poolRef[pe.Index] = pe.RefID
			}
		}
		decoder := cluster.NewArgsDescriptorDecoder(sc.Result, version)
		callSites := map[int]cluster.CallSiteInfo{}
		for _, c := range sc.Result.CallSites {
			callSites[c.RefID] = c
		}

		var sites, megamorphic, decoded, noReceiver, notCallSite, mismatches int
		for _, r := range sc.Ranges {
			fs, ok := sc.Slice(r)
			if !ok || len(fs.Code) == 0 {
				continue
			}
			insts := disasm.Disassemble(fs.Code, disasm.Options{BaseAddr: fs.VA})
			byPC := map[uint64][]disasm.ARM64PoolAccess{}
			for _, a := range disasm.ExtractARM64PoolAccesses(insts, nil) {
				if a.Kind == disasm.ARM64PoolAccessLoad && a.RegClass == disasm.ARM64PoolRegGPR {
					byPC[a.PC] = append(byPC[a.PC], a)
				}
			}
			for i, in := range insts {
				loads := byPC[in.Addr]
				if len(loads) != 2 || !strings.EqualFold(in.Mnemonic, "ldp") {
					continue
				}
				icIdx := -1
				var lr bool
				for _, l := range loads {
					switch l.Reg {
					case 5:
						icIdx = l.PoolIndex
					case 30:
						lr = true
					}
				}
				if icIdx < 0 || !lr {
					continue
				}
				sites++
				u, ok := callSites[poolRef[icIdx]]
				if !ok {
					notCallSite++
					if notCallSite <= 3 {
						t.Logf("%s: not a CallSiteData: pool %d ref %d cid %d display %q", name, icIdx, poolRef[icIdx], sc.Pool.RefCID[poolRef[icIdx]], sc.PoolDisplay[icIdx])
					}
					continue
				}
				if u.Megamorphic {
					megamorphic++
				}
				disp := receiverDisp(insts[:i])
				if disp < 0 {
					noReceiver++
					if noReceiver <= 2 {
						for j := max(0, i-8); j <= i; j++ {
							t.Logf("%s: noReceiver ctx %x %s", name, insts[j].Addr, insts[j].Text)
						}
					}
					continue
				}
				desc, ok := decoder.Decode(u.ArgsDescRef)
				if !ok {
					t.Errorf("%s: %x: args_descriptor ref %d does not decode", name, in.Addr, u.ArgsDescRef)
					continue
				}
				decoded++
				if desc.Count != disp/8+1 {
					mismatches++
					t.Errorf("%s: %s: descriptor count %d (type args %d) != receiver slot %d/8+1", name, strconv.FormatUint(in.Addr, 16), desc.Count, desc.TypeArgsLen, disp)
				}
			}
		}
		t.Logf("%s (%s): sites=%d megamorphic=%d decodedDescriptor=%d noReceiverLoad=%d notCallSite=%d mismatches=%d",
			name, version, sites, megamorphic, decoded, noReceiver, notCallSite, mismatches)
		if notCallSite != 0 {
			t.Errorf("%s: %d {R5,LR} LDP sites whose R5 is neither an UnlinkedCall nor a MegamorphicCache", name, notCallSite)
		}
		_ = sc.Close()
		ran++
	}
	if ran == 0 {
		t.Skip("no arm64 samples registered")
	}
}

// receiverDisp scans back for `ldr x0, [x15{, #d}]` and returns d (-1 if none
// before the previous call).
func receiverDisp(insts []disasm.Inst) int {
	for j := len(insts) - 1; j >= 0 && j >= len(insts)-12; j-- {
		// The disassembler spells it `LDR X0, [X15,#8]`; compare without spaces.
		text := strings.ReplaceAll(strings.ToLower(insts[j].Text), " ", "")
		if strings.HasPrefix(text, "blr") || strings.HasPrefix(text, "bl.") {
			return -1
		}
		if strings.HasPrefix(text, "ldrx0,[x15") {
			if strings.HasPrefix(text, "ldrx0,[x15]") {
				return 0
			}
			rest := strings.TrimPrefix(text, "ldrx0,[x15,#")
			rest = strings.TrimSuffix(rest, "]")
			v, err := strconv.ParseInt(rest, 0, 64)
			if err != nil {
				return -1
			}
			return int(v)
		}
	}
	return -1
}
