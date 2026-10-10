package typetrack

import "testing"

func TestMetricCountersMeasureUniqueFinalSitePopulation(t *testing.T) {
	ctx := &TypeContext{}

	ctx.hitMetric(metricHeader, 0x1000, &ctx.HeaderHits)
	ctx.hitMetric(metricHeader, 0x1000, &ctx.HeaderHits)
	ctx.hitMetric(metricHeader, 0x1004, &ctx.HeaderHits)
	if ctx.HeaderHits != 2 {
		t.Fatalf("HeaderHits=%d, want 2 unique PCs", ctx.HeaderHits)
	}

	ctx.recordX86DispatchMetric(0x2000, x86DispatchMetricNoClassTop)
	ctx.recordX86DispatchMetric(0x2000, x86DispatchMetricNoClassTop)
	if ctx.X86DispatchNoClass != 1 || ctx.X86DispatchClassTop != 1 {
		t.Fatalf("duplicate x86 dispatch visit inflated counters: no_class=%d top=%d", ctx.X86DispatchNoClass, ctx.X86DispatchClassTop)
	}
	ctx.recordX86DispatchMetric(0x2000, x86DispatchMetricResolved)
	if ctx.X86DispatchNoClass != 0 || ctx.X86DispatchClassTop != 0 || ctx.X86DispatchResolved != 1 {
		t.Fatalf("x86 dispatch final category not replaced: no_class=%d top=%d resolved=%d",
			ctx.X86DispatchNoClass, ctx.X86DispatchClassTop, ctx.X86DispatchResolved)
	}

	ctx.recordNarrowMetric(0x3000, narrowMetricNoType)
	ctx.recordNarrowMetric(0x3000, narrowMetricHit)
	if ctx.NarrowShape != 1 || ctx.NarrowNoType != 0 || ctx.NarrowHits != 1 {
		t.Fatalf("narrowing population mismatch: shape=%d no_type=%d hits=%d", ctx.NarrowShape, ctx.NarrowNoType, ctx.NarrowHits)
	}

	ctx.recordBLReturnMetric(0x4000, blReturnMetricNone)
	ctx.recordBLReturnMetric(0x4000, blReturnMetricObject)
	ctx.recordBLReturnMetric(0x4000, blReturnMetricObject)
	if ctx.BLTotal != 1 || ctx.BLHasExitType != 1 || ctx.BLExitKnown != 1 {
		t.Fatalf("direct-call population mismatch: total=%d has_exit=%d object_exit=%d", ctx.BLTotal, ctx.BLHasExitType, ctx.BLExitKnown)
	}
}
