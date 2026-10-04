package render

import (
	"fmt"
	"sort"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/signal"
)

// effectiveSignalSeverity is the presentation-level alert severity. SignalFunc
// severity describes potential impact if the classification is correct; the
// producer confidence describes how strongly the evidence supports that
// classification. Renderers must use both so a high-impact lexical keyword is
// not painted as a high-certainty red alert.
func effectiveSignalSeverity(impact, confidence string) string {
	impact = strings.ToLower(strings.TrimSpace(impact))
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high", "exact":
		return impact
	case "medium":
		if impact == "high" {
			return "medium"
		}
		return impact
	default:
		return "low"
	}
}

// signalRenderableEdges keeps every call-site record whose caller is a real
// function in the signal graph. The target may be external, absent (unresolved),
// or runtime-only; those distinctions are rendered as evidence rather than
// traversed as static function relations.
func signalRenderableEdges(g *signal.SignalGraph) []signal.SignalEdge {
	if g == nil {
		return nil
	}
	known := make(map[string]bool, len(g.Funcs))
	for _, f := range g.Funcs {
		known[f.Name] = true
	}
	out := make([]signal.SignalEdge, 0, len(g.Edges))
	for _, e := range g.Edges {
		if !known[e.From] {
			continue
		}
		out = append(out, e)
	}
	sortSignalEdges(out)
	return out
}

// signalTraversalEdges is the conservative static projection used for BFS,
// caller/callee navigation, and path construction. Runtime observations,
// unresolved sites, and external targets never become static graph vertices.
func signalTraversalEdges(g *signal.SignalGraph) []signal.SignalEdge {
	if g == nil {
		return nil
	}
	known := make(map[string]bool, len(g.Funcs))
	for _, f := range g.Funcs {
		known[f.Name] = true
	}
	out := make([]signal.SignalEdge, 0, len(g.Edges))
	for _, e := range g.Edges {
		if !known[e.From] || !known[e.To] || e.To == "" || !isSupportedCallKind(e.Kind) || !isStaticSignalResolution(e.Resolution) {
			continue
		}
		out = append(out, e)
	}
	sortSignalEdges(out)
	return out
}

func isStaticSignalResolution(resolution string) bool {
	switch resolution {
	case signal.ResolutionDirect, signal.ResolutionMonomorphic, signal.ResolutionPolymorphicCandidate:
		return true
	default:
		return false
	}
}

func isKnownSignalResolution(resolution string) bool {
	return isStaticSignalResolution(resolution) || resolution == signal.ResolutionUnresolved ||
		resolution == signal.ResolutionAddressOnly || resolution == signal.ResolutionRuntimeObserved || resolution == signal.ResolutionUnsupported
}

func sortSignalEdges(edges []signal.SignalEdge) {
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.FromPC != b.FromPC {
			return a.FromPC < b.FromPC
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Resolution != b.Resolution {
			return a.Resolution < b.Resolution
		}
		if a.Via != b.Via {
			return a.Via < b.Via
		}
		if a.TargetAddress != b.TargetAddress {
			return a.TargetAddress < b.TargetAddress
		}
		return a.RuntimeAgreement < b.RuntimeAgreement
	})
}

type signalEvidenceRelation struct {
	from      string
	nodeKey   string
	nodeLabel string
	prov      string
	edgeLabel string
}

func signalEvidenceRelations(g *signal.SignalGraph, visibleSources map[string]bool) []signalEvidenceRelation {
	if g == nil {
		return nil
	}
	known := make(map[string]bool, len(g.Funcs))
	for _, f := range g.Funcs {
		known[f.Name] = true
	}
	edges := signalRenderableEdges(g)
	type siteKey struct{ from, pc, kind, via string }
	listedBySite := make(map[siteKey]int)
	for _, e := range edges {
		if e.Resolution == signal.ResolutionPolymorphicCandidate && e.To != "" {
			listedBySite[siteKey{e.From, e.FromPC, e.Kind, e.Via}]++
		}
	}

	var out []signalEvidenceRelation
	seenGap := make(map[siteKey]bool)
	for _, e := range edges {
		if !visibleSources[e.From] {
			continue
		}
		site := siteKey{e.From, e.FromPC, e.Kind, e.Via}
		siteSuffix := e.From + "\x00" + e.FromPC + "\x00" + e.Kind + "\x00" + e.Via
		if !isKnownSignalResolution(e.Resolution) {
			out = append(out, signalEvidenceRelation{
				from: e.From, nodeKey: "\x00signal-invalid-resolution\x00" + siteSuffix + "\x00" + e.To,
				nodeLabel: "invalid/missing resolution @ " + signalEdgePC(e),
				prov:      ProvUnresolved, edgeLabel: "schema-invalid resolution",
			})
			continue
		}
		switch e.Resolution {
		case signal.ResolutionUnsupported:
			out = append(out, signalEvidenceRelation{
				from: e.From, nodeKey: "\x00signal-unsupported-kind\x00" + siteSuffix,
				nodeLabel: fmt.Sprintf("unsupported call kind %q @ %s", e.Kind, signalEdgePC(e)),
				prov:      ProvUnresolved, edgeLabel: "unsupported call kind",
			})
		case signal.ResolutionRuntimeObserved:
			if e.To == "" {
				continue
			}
			label := "runtime observed: " + e.To
			if e.RuntimeObservations > 0 {
				label += fmt.Sprintf(" ×%d", e.RuntimeObservations)
			}
			edgeLabel := "runtime"
			if e.RuntimeAgreement != "" {
				edgeLabel += " " + string(e.RuntimeAgreement)
			}
			out = append(out, signalEvidenceRelation{
				from: e.From, nodeKey: "\x00signal-runtime\x00" + siteSuffix + "\x00" + e.To,
				nodeLabel: label, prov: ProvRuntime, edgeLabel: edgeLabel,
			})
		case signal.ResolutionUnresolved:
			label := "unresolved indirect @ " + signalEdgePC(e)
			if e.Via != "" {
				label += "\nvia " + e.Via
			}
			out = append(out, signalEvidenceRelation{
				from: e.From, nodeKey: "\x00signal-unresolved\x00" + siteSuffix,
				nodeLabel: label, prov: ProvUnresolved, edgeLabel: "unresolved",
			})
		case signal.ResolutionAddressOnly:
			out = append(out, signalEvidenceRelation{
				from: e.From, nodeKey: "\x00signal-address\x00" + siteSuffix,
				nodeLabel: "direct target " + e.TargetAddress + " @ " + signalEdgePC(e),
				prov:      ProvDirect, edgeLabel: "address only",
			})
		default:
			if e.To != "" && !known[e.To] {
				out = append(out, signalEvidenceRelation{
					from: e.From, nodeKey: "\x00signal-external\x00" + siteSuffix + "\x00" + e.To,
					nodeLabel: "external static target: " + e.To,
					prov:      signalEdgeProvenance(e), edgeLabel: "external",
				})
			}
		}

		if e.Resolution == signal.ResolutionPolymorphicCandidate && !seenGap[site] {
			seenGap[site] = true
			listed := listedBySite[site]
			switch {
			case e.CandidateCountKnown && e.CandidateCount > listed:
				out = append(out, signalEvidenceRelation{
					from: e.From, nodeKey: "\x00signal-incomplete\x00" + siteSuffix,
					nodeLabel: fmt.Sprintf("+%d unlisted candidates @ %s", e.CandidateCount-listed, signalEdgePC(e)),
					prov:      ProvUnresolved, edgeLabel: "candidate set incomplete",
				})
			case !e.CandidateCountKnown:
				out = append(out, signalEvidenceRelation{
					from: e.From, nodeKey: "\x00signal-candidate-count-unknown\x00" + siteSuffix,
					nodeLabel: "candidate count unknown @ " + signalEdgePC(e),
					prov:      ProvUnresolved, edgeLabel: "candidate completeness unknown",
				})
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.from != b.from {
			return a.from < b.from
		}
		if a.nodeKey != b.nodeKey {
			return a.nodeKey < b.nodeKey
		}
		return a.edgeLabel < b.edgeLabel
	})
	return out
}

func signalEdgePC(e signal.SignalEdge) string {
	pc := strings.TrimSpace(e.FromPC)
	if pc == "" {
		return "unknown pc"
	}
	return pc
}

func signalEdgeProvenance(e signal.SignalEdge) string {
	return ClassifyEdgeProv(disasm.CallEdgeRecord{Kind: e.Kind, Via: e.Via})
}

func writeSignalEvidenceRelations(b *strings.Builder, relations []signalEvidenceRelation, t Theme) {
	for _, rel := range relations {
		id := dotID(rel.nodeKey)
		color := edgeColor(rel.prov, t)
		fmt.Fprintf(b, "  %s [label=%q, shape=plaintext, style=\"\", fillcolor=none, fontcolor=%q, fontsize=8];\n",
			id, truncLabel(rel.nodeLabel, 80), color)
		attrs := fmt.Sprintf("color=%q, style=%q, arrowsize=0.4", color, edgeStyle(rel.prov))
		if rel.edgeLabel != "" {
			attrs += fmt.Sprintf(", label=%q, fontsize=7, fontcolor=%q", truncLabel(rel.edgeLabel, 36), color)
		}
		fmt.Fprintf(b, "  %s -> %s [%s];\n", dotID(rel.from), id, attrs)
	}
}
