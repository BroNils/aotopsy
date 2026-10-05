package stmt

import (
	"regexp"
	"strconv"
	"strings"
)

// A Dart string interpolation with more than one piece compiles to (SDK
// kernel_binary_flowgraph.cc BuildStringConcatenation, kernel_to_il.cc
// StringInterpolate; md5-identical 2.12.0..3.13.0, 2.10.0 without literal
// merging):
//
//	CreateArray(n)                         // AllocateArray
//	for each piece i: StoreIndexed(array, i, piece)
//	StaticCall(_StringBase._interpolate, argument_count = 1)   // the array
//
// So the pieces are the ELEMENT STORES of the array, never the call's
// arguments. FoldInterpolationArrayStmt rebuilds the template when -- and only
// when -- that whole sequence is visible and safe to move:
//
//	final t1 = AllocateArray(null, 12, n)..f15 = a..f19 = " v";   (or plain stores)
//	t1.f23 = b;
//	stack_sp = t1;                         // the pushed call argument
//	return _StringBase._interpolate(null, t1, x);
//	->
//	return "$a v$b";
//
// Real output shows three shapes, all handled:
//
//   - the array in a temp (`final t1 = AllocateArray(...)`), stores through `t1.fN`;
//   - the array pushed inline (`stack_sp = AllocateArray(...)..f15 = a..f19 = b;`)
//     followed directly by the call, whose arguments are not shown at all
//     (`_StringBase._interpolate()`): the pushed array IS the single argument;
//   - the temp copied into a frame slot (`local_m16 = t1;`) and stored through
//     either name; this alias is only dropped when the call overwrites it
//     (`local_m16 = _StringBase._interpolate();`), so no later read can exist.
//
// Element i of an Array lives at a fixed tagged offset, from
// runtime_offsets_extracted.h (Array_data_offset, all supported versions):
//
//	uncompressed arm64/x64 : data at 24  => f23 + 8*i
//	compressed (>= 2.14.0) : data at 16  => f15 + 4*i
//
// The fold refuses (leaves everything untouched) unless the stores are exactly
// indices 0..n-1 in increasing order with that stride, the array is not used
// anywhere else, no construct sits between allocation and call (a conditional
// element must block the fold), every piece survives being evaluated at the call
// (pieceSurvivesMove), and -- when AllocateArray still shows its length -- the
// length agrees (n, or 2n for a Smi-tagged immediate).
var (
	allocArrayDeclRe = regexp.MustCompile(`^(?:final\s+)?([A-Za-z_]\w*)\s*=\s*AllocateArray\(`)
	elemStoreRe      = regexp.MustCompile(`^([A-Za-z_]\w*)\.f(\d+)\s*=\s*(.+);$`)
	rawElemStoreRe   = regexp.MustCompile(`^\*\(\(([A-Za-z_]\w*) \+ (\d+)\)\) = (.+);$`)
	// `V.fN.f0 = e;` is how the emitter prints a store through the computed
	// address V+N (the array store that needs a write barrier).
	derefElemStoreRe = regexp.MustCompile(`^([A-Za-z_]\w*)\.f(\d+)\.f0 = (.+);$`)
	cascadeStoreRe   = regexp.MustCompile(`\.\.f(\d+) = `)
	maskSuffixRe     = regexp.MustCompile(`\s*&\s*0xffffffff$`)
	aliasCopyRe      = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*);$`)
	callLhsRe        = regexp.MustCompile(`^(?:final\s+(?:\w+\s+)?)?([A-Za-z_]\w*)\s*=\s*`)
)

// parseAllocArray parses `[final ]V = AllocateArray(args)[..fN = e]...;`.
// It returns the variable, the top-level args, and the cascade stores in order.
func parseAllocArray(text string) (v string, args []string, offs []int, vals []string, ok bool) {
	m := allocArrayDeclRe.FindStringSubmatchIndex(text)
	if m == nil || !strings.HasSuffix(text, ";") {
		return
	}
	v = text[m[2]:m[3]]
	open := m[1] - 1
	closeIdx, balanced := matchParen(text, open)
	if !balanced {
		return "", nil, nil, nil, false
	}
	args = splitInterpolationParts(text[open+1 : closeIdx])
	rest := strings.TrimSuffix(text[closeIdx+1:], ";")
	if rest == "" {
		return v, args, nil, nil, true
	}
	if !strings.HasPrefix(rest, "..f") {
		return "", nil, nil, nil, false
	}
	locs := cascadeStoreRe.FindAllStringSubmatchIndex(rest, -1)
	for i, l := range locs {
		off, err := strconv.Atoi(rest[l[2]:l[3]])
		if err != nil {
			return "", nil, nil, nil, false
		}
		end := len(rest)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		offs = append(offs, off)
		vals = append(vals, strings.TrimSpace(rest[l[1]:end]))
	}
	return v, args, offs, vals, true
}

// parseElemStore recognises an element store into any of the names that refer
// to the array: `N.fK = e;`, `*((N + K)) = e;`, `N.fK.f0 = e;`.
func parseElemStore(t string, names map[string]bool) (off int, val string, ok bool) {
	for _, re := range []*regexp.Regexp{elemStoreRe, rawElemStoreRe, derefElemStoreRe} {
		m := re.FindStringSubmatch(t)
		if m == nil || !names[m[1]] {
			continue
		}
		n, err := strconv.Atoi(m[2])
		if err != nil {
			return 0, "", false
		}
		return n, strings.TrimSpace(m[3]), true
	}
	return 0, "", false
}

// stripCompressedMask removes the 32-bit zero-extension of a compressed object
// reference from a piece: `x & 0xffffffff` and `(x & 0xffffffff)` -> `x`. The
// stored value is an object; truncating it says nothing about the string.
func stripCompressedMask(piece string) string {
	piece = strings.TrimSpace(piece)
	if strings.HasPrefix(piece, "(") {
		if end, ok := matchParen(piece, 0); ok && end == len(piece)-1 {
			inner := strings.TrimSpace(piece[1:end])
			if stripped := maskSuffixRe.ReplaceAllString(inner, ""); stripped != inner {
				return strings.TrimSpace(stripped)
			}
			return piece
		}
	}
	return maskSuffixRe.ReplaceAllString(piece, "")
}

// pieceSurvivesMove reports whether evaluating piece at the interpolation call
// instead of at its store (body index at) gives the same value. The unrelated
// lines in between (others, only those after `at`) must not be able to change
// it:
//   - a piece containing a CALL is evaluated at the call site, so it may not
//     be reordered past any unrelated statement;
//   - a piece that reads memory (`.field`, `[..]`, `*..`) may not be moved past
//     a call or a memory store;
//   - a piece made of locals must not have any of them reassigned in between.
func pieceSurvivesMove(piece string, at int, others []int, body []Stmt) bool {
	isLiteral := len(piece) >= 2 && piece[0] == '"' && piece[len(piece)-1] == '"' && !strings.Contains(piece[1:len(piece)-1], `"`)
	if isLiteral {
		return true
	}
	hasCall := callInCondRe.MatchString(piece)
	readsMemory := strings.ContainsAny(piece, ".[*")
	roots := identRe.FindAllString(piece, -1)
	for _, o := range others {
		if o < at {
			continue
		}
		l := asLine(body[o])
		if l == nil {
			continue
		}
		t := strings.TrimSpace(l.Text)
		if hasCall {
			return false
		}
		if readsMemory && (callInCondRe.MatchString(t) || isMemoryStore(t)) {
			return false
		}
		if lhs := assignedRoot(t); lhs != "" {
			for _, r := range roots {
				if r == lhs {
					return false
				}
			}
		}
	}
	return true
}

var (
	assignLhsRe   = regexp.MustCompile(`^(?:final\s+(?:\w+\s+)?)?([A-Za-z_]\w*)\s*(?:\.\w+)?\s*[-+*/&|^]?=[^=]`)
	memoryStoreRe = regexp.MustCompile(`^(?:\*|[A-Za-z_][\w.]*\.f\d+\s*=|[A-Za-z_]\w*\[)`)
)

// assignedRoot returns the root identifier a line assigns to, or "".
func assignedRoot(t string) string {
	if m := assignLhsRe.FindStringSubmatch(t); m != nil {
		return m[1]
	}
	return ""
}

func isMemoryStore(t string) bool {
	return strings.HasPrefix(t, "*") || memoryStoreRe.MatchString(t) && strings.Contains(t, "=")
}

func elementIndices(offs []int) ([]int, bool) {
	if len(offs) == 0 {
		return nil, false
	}
	var base, stride int
	switch {
	case offs[0] == 23:
		base, stride = 23, 8
	case offs[0] == 15:
		base, stride = 15, 4
	default:
		return nil, false
	}
	idx := make([]int, len(offs))
	for i, o := range offs {
		if (o-base) < 0 || (o-base)%stride != 0 {
			return nil, false
		}
		idx[i] = (o - base) / stride
		if idx[i] != i { // exactly 0..n-1, in order
			return nil, false
		}
	}
	return idx, true
}

// FoldInterpolationArrayStmt rebuilds string templates from the array element
// stores (see the file comment).
func FoldInterpolationArrayStmt(stmts []Stmt) ([]Stmt, bool) {
	return mapBodies(stmts, foldInterpolationBody)
}

func foldInterpolationBody(body []Stmt) ([]Stmt, bool) {
	changed := false
	for i := 0; i < len(body); i++ {
		decl := asLine(body[i])
		if decl == nil {
			continue
		}
		v, args, offs, vals, ok := parseAllocArray(decl.Text)
		if !ok {
			continue
		}
		inlinePush := v == "stack_sp" // `stack_sp = AllocateArray(...)..`: the array is the pushed argument
		names := map[string]bool{v: true}
		drop := map[int]bool{i: true}
		callIdx := -1
		aliasVar := ""
		storeAt := make([]int, len(offs)) // body index of each piece's store (decl cascade = i)
		for k := range storeAt {
			storeAt[k] = i
		}
		var others []int // body indices of unrelated Lines between allocation and call
		prevPush := inlinePush
		nameWord := func(t string) bool {
			for n := range names {
				if regexp.MustCompile(`\b` + regexp.QuoteMeta(n) + `\b`).MatchString(t) {
					return true
				}
			}
			return false
		}
		for j := i + 1; j < len(body); j++ {
			l := asLine(body[j])
			if l == nil {
				if _, isV := body[j].(*Verbatim); isV {
					continue
				}
				break // a construct between allocation and call: pieces may be conditional
			}
			t := strings.TrimSpace(l.Text)
			if t == "" || strings.HasPrefix(t, "//") || LabelDeclRe.MatchString(t) {
				continue
			}
			if off, val, ok := parseElemStore(t, names); ok && !inlinePush {
				offs = append(offs, off)
				vals = append(vals, val)
				storeAt = append(storeAt, j)
				drop[j] = true
				prevPush = false
				continue
			}
			if !inlinePush {
				// `local_mN = V;` copies the array into a frame slot.
				if m := aliasCopyRe.FindStringSubmatch(t); m != nil && m[2] == v && aliasVar == "" && len(offs) == len(storeAt) && strings.HasPrefix(m[1], "local_") {
					aliasVar = m[1]
					names[aliasVar] = true
					drop[j] = true
					prevPush = false
					continue
				}
				pushed := false
				for n := range names {
					if t == "stack_sp = "+n+";" {
						pushed = true
					}
				}
				if pushed {
					drop[j] = true
					prevPush = true
					continue
				}
			}
			if interpolateCallRe.MatchString(t) {
				callIdx = j
				break
			}
			if nameWord(t) {
				break // the array escapes into some other statement
			}
			others = append(others, j)
			prevPush = false
		}
		if callIdx < 0 {
			continue
		}
		call := asLine(body[callIdx])
		cm := interpolateCallRe.FindStringSubmatchIndex(call.Text)
		if cm == nil || call.Text[cm[2]:cm[3]] != "_interpolate" {
			continue
		}
		open := strings.Index(call.Text[cm[0]:], "(") + cm[0]
		closeIdx, balanced := matchParen(call.Text, open)
		if !balanced {
			continue
		}
		callArgs := splitInterpolationParts(call.Text[open+1 : closeIdx])
		usesV := false
		for _, a := range callArgs {
			if names[strings.TrimSpace(a)] {
				usesV = true
			}
		}
		// The array reaches the call either as a visible argument or as the value
		// just pushed on the stack (the call's argument list is not shown then).
		if !usesV && !prevPush {
			continue
		}
		if aliasVar != "" {
			// The alias copy is dropped only when the call overwrites it.
			m := callLhsRe.FindStringSubmatch(call.Text)
			if m == nil || m[1] != aliasVar {
				continue
			}
		}
		if inlinePush && len(others) > 0 {
			continue // the call must directly follow the pushed array
		}
		if _, ok := elementIndices(offs); !ok {
			continue
		}
		n := len(offs)
		if len(args) >= 2 { // the length is still shown: it must agree
			if length, err := strconv.Atoi(strings.TrimSpace(args[1])); err == nil && length != n && length != 2*n {
				continue
			}
		}
		pieces := make([]string, n)
		pure := true
		for k, val := range vals {
			pieces[k] = stripCompressedMask(val)
			if !pieceSurvivesMove(pieces[k], storeAt[k], others, body) {
				pure = false
				break
			}
		}
		if !pure {
			continue
		}
		template := formatStringInterpolation("[" + strings.Join(pieces, ", ") + "]")
		call.Text = call.Text[:cm[0]] + template + call.Text[closeIdx+1:]

		kept := make([]Stmt, 0, len(body))
		for k, s := range body {
			if !drop[k] {
				kept = append(kept, s)
			}
		}
		body = kept
		changed = true
		i = -1 // restart: indices moved
	}
	return body, changed
}
