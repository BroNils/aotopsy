package decompiler

// Dominator analysis over a FuncIR's CFG, and the back-edge test built on it.
//
// This exists because loop recovery used to ask a question it could not
// answer from block addresses alone: "is this edge a back edge?" The old test
// was `target.StartVA <= source.StartVA` -- any branch that goes backward in
// the code layout. That is not what a back edge is, and in Dart AOT output the
// difference is large, because the compiler emits two backward branches that
// have nothing to do with loops:
//
//   - The stack-overflow check. `cmp SP, [THR + stack_limit]; b.ls <slow>`
//     puts the slow path at the end of the function, and the slow path ends
//     with an unconditional branch BACK to the instruction after the check.
//     Measured shape: an unconditional jump of -26 to -88 bytes into the
//     middle of the function.
//
//   - The monomorphic entry check. A Code object has several entry points;
//     the monomorphic one compares the receiver's cid and, on a miss, jumps
//     back to the start. Measured shape: `cmp/jne` of about -21 bytes from a
//     block starting 7-8 bytes into the function, in `dyn:` forwarders and
//     constructors.
//
// Counting those as loops marked 63-98 functions in every 400 as containing a
// loop when their source has none -- 16-25% of the corpus sample -- which in
// turn made finding 019's "10 functions fail loop recovery" a measurement over
// a largely fictitious population.
//
// The textbook definition has no such failure mode: an edge u->v is a back
// edge exactly when v dominates u. Neither compiler pattern above satisfies
// it, because in both cases control can reach the source block without passing
// through the target.

// dominators returns idom[b] = immediate dominator of block b, with
// idom[entry] = entry, and -1 for blocks not reachable from the entry.
//
// Cooper-Harvey-Kennedy: iterate the intersection of predecessors' dominator
// sets over reverse post-order until nothing changes. Chosen over the bit-set
// dataflow formulation because the CFGs here are small and this needs no
// allocation proportional to |blocks|^2.
func dominators(fir *FuncIR) []int {
	n := len(fir.Blocks)
	idom := make([]int, n)
	for i := range idom {
		idom[i] = -1
	}
	if n == 0 {
		return idom
	}

	order := reversePostOrder(fir)
	// rpoNum[b] is b's position in RPO; unreachable blocks keep -1 and are
	// skipped entirely, since "dominated by the entry" is meaningless for a
	// block the entry cannot reach.
	rpoNum := make([]int, n)
	for i := range rpoNum {
		rpoNum[i] = -1
	}
	for i, b := range order {
		rpoNum[b] = i
	}

	entry := 0
	idom[entry] = entry

	// intersect walks two blocks up the dominator tree until they meet. Both
	// arguments must already have an idom, which the RPO order guarantees for
	// at least one predecessor of every reachable block.
	intersect := func(a, b int) int {
		for a != b {
			for rpoNum[a] > rpoNum[b] {
				a = idom[a]
			}
			for rpoNum[b] > rpoNum[a] {
				b = idom[b]
			}
		}
		return a
	}

	for changed := true; changed; {
		changed = false
		for _, b := range order {
			if b == entry {
				continue
			}
			newIdom := -1
			for _, p := range fir.Blocks[b].Preds {
				if p < 0 || p >= n || rpoNum[p] < 0 || idom[p] < 0 {
					continue
				}
				if newIdom < 0 {
					newIdom = p
					continue
				}
				newIdom = intersect(p, newIdom)
			}
			if newIdom >= 0 && idom[b] != newIdom {
				idom[b] = newIdom
				changed = true
			}
		}
	}
	return idom
}

// reversePostOrder returns the reachable blocks in reverse post-order from
// block 0, which is the entry: FuncIR is built by splitting the function's
// instruction stream at branch targets, so the lowest-addressed block is the
// one control starts in.
func reversePostOrder(fir *FuncIR) []int {
	n := len(fir.Blocks)
	visited := make([]bool, n)
	post := make([]int, 0, n)

	// Iterative DFS: these CFGs are small, but a recursive walk would still be
	// bounded only by block count, and the emitter already has one recursion
	// depth limit too many.
	type frame struct{ id, next int }
	stack := []frame{{0, 0}}
	visited[0] = true
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		succs := fir.Blocks[top.id].Succs
		if top.next < len(succs) {
			s := succs[top.next].BlockID
			top.next++
			if s >= 0 && s < n && !visited[s] {
				visited[s] = true
				stack = append(stack, frame{s, 0})
			}
			continue
		}
		post = append(post, top.id)
		stack = stack[:len(stack)-1]
	}

	for i, j := 0, len(post)-1; i < j; i, j = i+1, j-1 {
		post[i], post[j] = post[j], post[i]
	}
	return post
}

// dominates reports whether a dominates b, walking b up the dominator tree.
func dominates(idom []int, a, b int) bool {
	if a < 0 || b < 0 || a >= len(idom) || b >= len(idom) {
		return false
	}
	if idom[b] < 0 {
		return false // b unreachable: nothing dominates it
	}
	for {
		if a == b {
			return true
		}
		if b == idom[b] {
			return false // reached the entry without finding a
		}
		b = idom[b]
	}
}
