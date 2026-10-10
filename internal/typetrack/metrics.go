package typetrack

// Telemetry in typetrack is keyed by machine-code PC, not by transfer-function
// invocation. PCs here are image virtual addresses, so one PC denotes one
// physical instruction site even when analysis revisits it or multiple semantic
// names alias the same code range. CFG worklists revisit blocks and
// RunInterprocedural re-analyzes functions; counting every visit makes a "hit"
// counter a convergence/runtime counter instead of the population of code sites
// that actually fire a rule.

const (
	metricPPLoad           = "pp_load"
	metricPPHit            = "pp_hit"
	metricHeader           = "header"
	metricUBFX             = "class_id_extract"
	metricADDClass         = "dispatch_class_arith"
	metricDispatch         = "dispatch_resolved"
	metricAllocStub        = "allocation_stub"
	metricBLTotal          = "direct_call"
	metricArgsDescReceiver = "argsdesc_receiver"
	metricFieldDeclared    = "declared_field_type"
	metricX86DispatchShape = "x86_dispatch_shape"
)

func (ctx *TypeContext) hitMetric(key string, pc uint64, counter *int) {
	if ctx == nil || counter == nil {
		return
	}
	if ctx.metricSites == nil {
		ctx.metricSites = make(map[string]map[uint64]struct{})
	}
	sites := ctx.metricSites[key]
	if sites == nil {
		sites = make(map[uint64]struct{})
		ctx.metricSites[key] = sites
	}
	if _, exists := sites[pc]; exists {
		return
	}
	sites[pc] = struct{}{}
	*counter++
}

type x86DispatchMetricState uint8

const (
	x86DispatchMetricNone x86DispatchMetricState = iota
	x86DispatchMetricResolved
	x86DispatchMetricNoTable
	x86DispatchMetricNoClassTop
	x86DispatchMetricNoClassUnknownCID
	x86DispatchMetricNoClassOther
)

func (ctx *TypeContext) recordX86DispatchMetric(pc uint64, next x86DispatchMetricState) {
	if ctx == nil {
		return
	}
	if ctx.x86DispatchMetricByPC == nil {
		ctx.x86DispatchMetricByPC = make(map[uint64]x86DispatchMetricState)
	}
	prev := ctx.x86DispatchMetricByPC[pc]
	if prev == next {
		return
	}
	ctx.adjustX86DispatchMetric(prev, -1)
	ctx.adjustX86DispatchMetric(next, 1)
	if next == x86DispatchMetricNone {
		delete(ctx.x86DispatchMetricByPC, pc)
	} else {
		ctx.x86DispatchMetricByPC[pc] = next
	}
}

func (ctx *TypeContext) adjustX86DispatchMetric(s x86DispatchMetricState, delta int) {
	switch s {
	case x86DispatchMetricResolved:
		ctx.X86DispatchResolved += delta
	case x86DispatchMetricNoTable:
		ctx.X86DispatchNoTable += delta
	case x86DispatchMetricNoClassTop:
		ctx.X86DispatchNoClass += delta
		ctx.X86DispatchClassTop += delta
	case x86DispatchMetricNoClassUnknownCID:
		ctx.X86DispatchNoClass += delta
		ctx.X86DispatchClassUnknownCID += delta
	case x86DispatchMetricNoClassOther:
		ctx.X86DispatchNoClass += delta
		ctx.X86DispatchClassOther += delta
	}
}

type blrMetricState uint8

const (
	blrMetricNone blrMetricState = iota
	blrMetricKnownDispatch
	blrMetricKnownDispatchSelector
	blrMetricObject
	blrMetricStub
	blrMetricTop
	blrMetricUnreachable
	blrMetricOther
)

func (ctx *TypeContext) recordBLRMetric(pc uint64, next blrMetricState) {
	if ctx == nil {
		return
	}
	if ctx.blrMetricByPC == nil {
		ctx.blrMetricByPC = make(map[uint64]blrMetricState)
	}
	prev := ctx.blrMetricByPC[pc]
	if prev == next {
		return
	}
	ctx.adjustBLRMetric(prev, -1)
	ctx.adjustBLRMetric(next, 1)
	ctx.blrMetricByPC[pc] = next
}

func (ctx *TypeContext) adjustBLRMetric(s blrMetricState, delta int) {
	switch s {
	case blrMetricKnownDispatch:
		ctx.BLRAtKnownDispatch += delta
	case blrMetricKnownDispatchSelector:
		ctx.BLRAtKnownDispatchSel += delta
	case blrMetricObject:
		ctx.BLRAtObject += delta
	case blrMetricStub:
		ctx.BLRAtStub += delta
	case blrMetricTop:
		ctx.BLRAtTop += delta
	case blrMetricUnreachable:
		ctx.BLRAtUnreachable += delta
	case blrMetricOther:
		ctx.BLRAtOther += delta
	}
}

type narrowMetricState uint8

const (
	narrowMetricNone narrowMetricState = iota
	narrowMetricNoType
	narrowMetricHit
)

func (ctx *TypeContext) recordNarrowMetric(pc uint64, next narrowMetricState) {
	if ctx == nil {
		return
	}
	ctx.hitMetric("narrow_shape", pc, &ctx.NarrowShape)
	if ctx.narrowMetricByPC == nil {
		ctx.narrowMetricByPC = make(map[uint64]narrowMetricState)
	}
	prev := ctx.narrowMetricByPC[pc]
	if prev == next {
		return
	}
	ctx.adjustNarrowMetric(prev, -1)
	ctx.adjustNarrowMetric(next, 1)
	ctx.narrowMetricByPC[pc] = next
}

func (ctx *TypeContext) adjustNarrowMetric(s narrowMetricState, delta int) {
	switch s {
	case narrowMetricNoType:
		ctx.NarrowNoType += delta
	case narrowMetricHit:
		ctx.NarrowHits += delta
	}
}

type blReturnMetricState uint8

const (
	blReturnMetricNone blReturnMetricState = iota
	blReturnMetricNonObject
	blReturnMetricObject
)

func (ctx *TypeContext) recordBLReturnMetric(pc uint64, next blReturnMetricState) {
	if ctx == nil {
		return
	}
	ctx.hitMetric(metricBLTotal, pc, &ctx.BLTotal)
	if ctx.blReturnMetricByPC == nil {
		ctx.blReturnMetricByPC = make(map[uint64]blReturnMetricState)
	}
	prev := ctx.blReturnMetricByPC[pc]
	if prev == next {
		return
	}
	ctx.adjustBLReturnMetric(prev, -1)
	ctx.adjustBLReturnMetric(next, 1)
	ctx.blReturnMetricByPC[pc] = next
}

func (ctx *TypeContext) adjustBLReturnMetric(s blReturnMetricState, delta int) {
	switch s {
	case blReturnMetricNonObject:
		ctx.BLHasExitType += delta
	case blReturnMetricObject:
		ctx.BLHasExitType += delta
		ctx.BLExitKnown += delta
	}
}
