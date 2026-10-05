package decompiler

import (
	"fmt"
	"regexp"
	"strconv"
)

// Class-id tests are how the VM compiles `x is T`, `x as T` and the arms of
// an inlined polymorphic call (EmitTestAndCall / GenerateCidRangesCheck in
// flow_graph_compiler.cc): the object's class id is extracted
// (`classId(x)`) and compared with one cid or a cid RANGE.
//
// annotateClassIDCondition appends the class NAMES at the ends of the tested
// cid range as a trailing comment. It deliberately does not claim which type
// `T` the test implements: HierarchyInfo::BuildRangesFor (il.cc) builds the
// range from every concrete SUBTYPE of T (`extends` AND `implements`),
// merging across abstract/top-level "don't care" classes, so a range alone
// does not identify T. The names are facts read from the class table.

var (
	// ((classId(x) - lo) & MASK) > ((n) & MASK), with or without the
	// redundant parentheses the pretty printer may drop.
	// The operand is any expression (`x1`, `(arg0.f75 & 0xffffffff)`, ...).
	reCIDRangeOutside = regexp.MustCompile(`^\(*classId\((.+)\) - (\d+)\)* & 0x[f]+\)+ > \(*(\d+)\)* & 0x[f]+\)+$`)
	reCIDEqual        = regexp.MustCompile(`^classId\((.+)\) (==|!=) (\d+)$`)
)

func annotateClassIDCondition(f *FuncIR, cond string) string {
	if f == nil || f.ClassNameForCID == nil {
		return cond
	}
	if m := reCIDRangeOutside.FindStringSubmatch(cond); m != nil {
		lo, err1 := strconv.Atoi(m[2])
		span, err2 := strconv.Atoi(m[3])
		if err1 != nil || err2 != nil || span < 0 {
			return cond
		}
		first, last := f.ClassNameForCID(lo), f.ClassNameForCID(lo+span)
		if first == "" || last == "" {
			return cond
		}
		return fmt.Sprintf("%s /* %s outside cid %d..%d: %s */", cond, m[1], lo, lo+span, cidSpanLabel(first, last))
	}
	if m := reCIDEqual.FindStringSubmatch(cond); m != nil {
		cid, err := strconv.Atoi(m[3])
		if err != nil {
			return cond
		}
		if name := f.ClassNameForCID(cid); name != "" {
			return fmt.Sprintf("%s /* cid %d = %s */", cond, cid, name)
		}
	}
	return cond
}

func cidSpanLabel(first, last string) string {
	if first == last {
		return first
	}
	return first + ".." + last
}
