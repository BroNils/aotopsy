package cluster

import (
	"fmt"
	"math"

	"aotopsy/internal/dartfmt"
)

// CodeSourceMap decoding.
//
// A CodeSourceMap is a little bytecode that, when run, tracks a stack of
// inlined functions and the current token position as the PC advances. It is
// what maps a PC back to "which (possibly inlined) function, at which source
// position".
//
// Transcribed from the Dart SDK @ 3.9.2:
//   - CodeSourceMapOps (runtime/vm/code_descriptors.h) for the bit layout
//   - CodeSourceMapOps::Read (runtime/vm/code_descriptors.cc) for the encoding
//   - CodeSourceMapBuilder for op semantics

// CodeSourceMap opcodes.
const (
	CSMChangePosition uint8 = 0
	CSMAdvancePC      uint8 = 1
	CSMPushFunction   uint8 = 2
	CSMPopFunction    uint8 = 3
	CSMNullCheck      uint8 = 4
)

// CSMEntry is one PC in a decoded CodeSourceMap, with the inlining state that
// applies at that PC.
type CSMEntry struct {
	// PCOffset is relative to the Code's payload start.
	PCOffset uint32
	// TokenPos is the raw serialized TokenPosition of the innermost frame, or
	// CSMNoPosition when none has been set yet.
	//
	// This is NOT a line number. Turning it into file:line needs the owning
	// Script's line_starts table; see CodeSourceMapInfo.
	TokenPos int32
	// inlineStack is a persistent stack node. Entries share unchanged stack
	// state instead of copying the entire inline stack on every AdvancePC.
	// Materialize it only through InlineStack(), where a consumer actually
	// needs the IDs.
	inlineStack *csmInlineFrame
}

type csmInlineFrame struct {
	id     int32
	parent *csmInlineFrame
	depth  int
}

// InlineDepth returns the number of active inlined frames at this entry.
func (e CSMEntry) InlineDepth() int {
	if e.inlineStack == nil {
		return 0
	}
	return e.inlineStack.depth
}

// InlineStack materializes the inlined-function IDs, outermost first.
// DecodeCodeSourceMap itself retains only persistent linked stack nodes, so a
// stream with a deep stack and many AdvancePC operations remains linear in the
// number of operations instead of retaining O(entries*depth) copied slices.
func (e CSMEntry) InlineStack() []int32 {
	if e.inlineStack == nil {
		return nil
	}
	out := make([]int32, e.inlineStack.depth)
	for frame := e.inlineStack; frame != nil; frame = frame.parent {
		out[frame.depth-1] = frame.id
	}
	return out
}

// CSMNoPosition marks "no token position recorded yet".
const CSMNoPosition int32 = -1

// CodeSourceMapInfo is one decoded CodeSourceMap object.
//
// LIMITATION, and it is a hard one: this yields PC -> (inline function stack,
// raw token position). PC -> file:line is IMPOSSIBLE for a release build, not
// merely unimplemented.
//
// A TokenPosition is a byte offset into the Dart source; turning it into a line
// needs Script.line_starts. From UntaggedScript::to_snapshot (raw_object.h
// @ 3.9.2):
//
//	case Snapshot::kFullAOT:
//	#if defined(PRODUCT)
//	      return ... &url_;          // serializes url ONLY
//	#else
//	      return ... &resolved_url_; // url + resolved_url
//	#endif
//
// Since ReadFromTo runs from VISIT_FROM(url) to that bound, a PRODUCT AOT
// Script carries exactly ONE ref -- url. line_starts, source, debug_positions
// and kernel_program_info are all excluded by construction. specScript agrees
// (NumRefs: 1), which is also why the fill stream stays aligned.
//
// So the usable product is the inlining stack -- real, verified, and not
// obtainable any other way -- plus a token position that is only meaningful if
// some future non-PRODUCT input ever supplies line_starts.
type CodeSourceMapInfo struct {
	RefID   int
	Entries []CSMEntry
}

// DecodeCodeSourceMap runs the CodeSourceMap bytecode and records the state at
// every PC the stream advances to.
//
// Encoding: each op is a single value read with ReadStream::Read<int32_t>(),
// packed as
//
//	op   = n & 0x7        // OpField, kOpBits == 3
//	arg1 = n >> 3         // ArgField, sign-extended
//
// The arithmetic shift reproduces what the SDK spells out as a bitfield decode
// plus an explicit sign fix-up (`if (*arg1 > kMaxArgValue) *arg1 |= kSignBits`),
// because ArgField occupies the top 29 bits.
//
// CRITICAL: `Read<int32_t>()` is Dart's own marker varint
// (`Read<T>(kEndByteMarker)` in datastream.h, the "marker 192" scheme this
// codebase already implements as dartfmt.Stream.ReadTagged32) -- it is NOT
// SLEB128. PcDescriptors, by contrast, calls ReadSLEB128<int32_t>() explicitly.
// The two neighbouring formats genuinely differ. Decoding this one as SLEB128
// parses without error and yields plausible-looking garbage: it produced
// negative inlined-function ids (-127976) on a real 3.9.2 snapshot, which is
// how the mistake was caught.
//
// kChangePosition carries a SECOND value only under DART_PRECOMPILER with
// dwarf_stack_traces_mode, and the SDK notes those maps "are not serialized in
// precompiled snapshots" -- so a snapshot reader must read exactly one value
// per op. Reading a phantom second value would desync everything after it.
func DecodeCodeSourceMap(payload []byte) ([]CSMEntry, error) {
	var entries []CSMEntry
	var pc int64
	tokenPos := CSMNoPosition
	var stack *csmInlineFrame
	s := dartfmt.NewStreamAt(payload, 0)

	// Record the state at the current PC. Called after every AdvancePC, since
	// that is what delimits one PC range from the next.
	record := func() {
		entries = append(entries, CSMEntry{
			PCOffset:    uint32(pc),
			TokenPos:    tokenPos,
			inlineStack: stack,
		})
	}

	for s.Position() < len(payload) {
		raw, err := s.ReadTagged32()
		if err != nil {
			return entries, fmt.Errorf("code_source_map: op: %w", err)
		}
		// ReadTagged32 returns the raw 32-bit pattern; reinterpret as signed
		// before the arithmetic shift so ArgField sign-extends.
		n := int32(raw)
		op := uint8(n & 0x7)
		arg := n >> 3

		switch op {
		case CSMChangePosition:
			tokenPos = arg
		case CSMAdvancePC:
			if arg < 0 {
				return entries, fmt.Errorf("code_source_map: negative pc advance %d", arg)
			}
			if int64(arg) > math.MaxUint32-pc {
				return entries, fmt.Errorf("code_source_map: pc_offset exceeds uint32: current=%d advance=%d", pc, arg)
			}
			pc += int64(arg)
			record()
		case CSMPushFunction:
			if arg < 0 {
				return entries, fmt.Errorf("code_source_map: negative inline function id %d", arg)
			}
			depth := 1
			if stack != nil {
				depth = stack.depth + 1
			}
			stack = &csmInlineFrame{id: arg, parent: stack, depth: depth}
		case CSMPopFunction:
			if stack == nil {
				// A pop without a matching push means the stream is not what we
				// think it is; report rather than silently continuing with a
				// bogus inline stack.
				return entries, fmt.Errorf("code_source_map: pop with empty inline stack")
			}
			stack = stack.parent
		case CSMNullCheck:
			// Records which name was null-checked; carries no PC or position
			// change, so nothing to track for our purposes.
		default:
			return entries, fmt.Errorf("code_source_map: unknown op %d", op)
		}
	}
	return entries, nil
}

// InlineStackAt returns the inline function stack and token position in effect
// at pcOffset, i.e. from the last entry at or before it.
func (c *CodeSourceMapInfo) InlineStackAt(pcOffset uint32) (stack []int32, tokenPos int32, ok bool) {
	best := -1
	for i := range c.Entries {
		if c.Entries[i].PCOffset <= pcOffset {
			best = i
			continue
		}
		break
	}
	if best < 0 {
		return nil, CSMNoPosition, false
	}
	return c.Entries[best].InlineStack(), c.Entries[best].TokenPos, true
}
