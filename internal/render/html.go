package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/strutil"
)

// WriteIndexHTML writes a small HTML page summarizing the disasm output.
func WriteIndexHTML(w io.Writer, stats CallgraphStats, unresTHR []disasm.UnresolvedTHRRecord, title string,
	hasCallgraphSVG, hasClassgraphSVG, hasReachableSVG bool,
	entryPoints []string, reachableCount int, cfgCount int) {

	blrPct := 0.0
	if stats.BLREdges > 0 {
		blrPct = float64(stats.BLRAnnotated) / float64(stats.BLREdges) * 100
	}

	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%s</title>
<style>
body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; font-size: 14px; color: #1A1A1A; background: #F5F5F5; margin: 2em; max-width: 900px; }
h1 { font-size: 18px; font-weight: 600; margin-bottom: 0.5em; }
h2 { font-size: 14px; font-weight: 600; margin-top: 1.5em; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
table { border-collapse: collapse; margin: 0.5em 0; }
th, td { text-align: left; padding: 3px 12px 3px 0; font-size: 13px; }
th { font-weight: 600; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.prov { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 4px; vertical-align: middle; }
a { color: #0B3D91; }
.bar { height: 8px; border-radius: 2px; display: inline-block; vertical-align: middle; }
.mbar { height: 6px; border-radius: 2px; display: inline-block; vertical-align: middle; background: #0B3D91; }
.ep { font-family: "Courier New", monospace; font-size: 12px; }
</style>
</head>
<body>
`, htmlEscape(title))

	_, _ = fmt.Fprintf(w, "<h1>%s</h1>\n", htmlEscape(title))

	// Summary table.
	_, _ = fmt.Fprintln(w, "<h2>Summary</h2>")
	_, _ = fmt.Fprintln(w, "<table>")
	_, _ = fmt.Fprintf(w, "<tr><td>Functions</td><td class=\"num\">%d</td></tr>\n", stats.TotalFunctions)
	_, _ = fmt.Fprintf(w, "<tr><td>Owner classes</td><td class=\"num\">%d</td></tr>\n", stats.UniqueOwners)
	_, _ = fmt.Fprintf(w, "<tr><td>Total edges</td><td class=\"num\">%d</td></tr>\n", stats.TotalEdges)
	_, _ = fmt.Fprintf(w, "<tr><td>BL (direct)</td><td class=\"num\">%d</td></tr>\n", stats.BLEdges)
	_, _ = fmt.Fprintf(w, "<tr><td>BLR (indirect)</td><td class=\"num\">%d</td></tr>\n", stats.BLREdges)
	_, _ = fmt.Fprintf(w, "<tr><td>BLR annotated</td><td class=\"num\">%d (%.1f%%)</td></tr>\n", stats.BLRAnnotated, blrPct)
	_, _ = fmt.Fprintf(w, "<tr><td>Entry points</td><td class=\"num\">%d</td></tr>\n", len(entryPoints))
	_, _ = fmt.Fprintf(w, "<tr><td>Reachable functions</td><td class=\"num\">%d</td></tr>\n", reachableCount)
	_, _ = fmt.Fprintf(w, "<tr><td>Unresolved THR</td><td class=\"num\">%d</td></tr>\n", len(unresTHR))
	if cfgCount > 0 {
		_, _ = fmt.Fprintf(w, "<tr><td>CFGs generated</td><td class=\"num\">%d</td></tr>\n", cfgCount)
	}
	_, _ = fmt.Fprintln(w, "</table>")

	// Provenance breakdown.
	_, _ = fmt.Fprintln(w, "<h2>Edge Provenance</h2>")
	_, _ = fmt.Fprintln(w, "<table>")
	_, _ = fmt.Fprintln(w, "<tr><th></th><th>Category</th><th>Count</th><th></th></tr>")
	provOrder := []string{ProvDirect, ProvTHR, ProvPP, ProvDispatch, ProvObject, ProvUnresolved}
	provLabels := map[string]string{
		ProvDirect:     "BL direct",
		ProvTHR:        "THR (runtime entry)",
		ProvPP:         "PP (object pool)",
		ProvDispatch:   "Dispatch table",
		ProvObject:     "Object field",
		ProvUnresolved: "Unresolved",
	}
	nasa := NASA
	provColors := map[string]string{
		ProvDirect:     nasa.EdgeDirect,
		ProvTHR:        nasa.EdgeTHR,
		ProvPP:         nasa.EdgePP,
		ProvDispatch:   nasa.EdgeDispatch,
		ProvObject:     nasa.EdgeObject,
		ProvUnresolved: nasa.EdgeUnresolved,
	}
	for _, prov := range provOrder {
		count := stats.ProvCounts[prov]
		if count == 0 {
			continue
		}
		color := provColors[prov]
		barW := 0
		if stats.TotalEdges > 0 {
			barW = count * 200 / stats.TotalEdges
			if barW < 2 {
				barW = 2
			}
		}
		_, _ = fmt.Fprintf(w, "<tr><td><span class=\"prov\" style=\"background:%s\"></span></td><td>%s</td><td class=\"num\">%d</td><td><span class=\"bar\" style=\"width:%dpx;background:%s\"></span></td></tr>\n",
			color, provLabels[prov], count, barW, color)
	}
	_, _ = fmt.Fprintln(w, "</table>")

	// Graphs — only link SVGs (dot files can't be opened in a browser).
	_, _ = fmt.Fprintln(w, "<h2>Graphs</h2>")
	_, _ = fmt.Fprint(w, "<p>")
	var links []string
	if hasReachableSVG {
		links = append(links, `<a href="reachable.svg">Reachable call tree</a>`)
	}
	if hasClassgraphSVG {
		links = append(links, `<a href="classgraph.svg">Class-level graph</a>`)
	}
	if hasCallgraphSVG {
		links = append(links, `<a href="callgraph.svg">Function-level graph</a>`)
	}
	if cfgCount > 0 {
		links = append(links, `<a href="cfg/">Per-function CFGs</a>`)
	}
	if len(links) == 0 {
		_, _ = fmt.Fprint(w, `<span style="color:#9E9E9E">Run without --no-dot to generate SVGs</span>`)
	} else {
		for i, link := range links {
			if i > 0 {
				_, _ = fmt.Fprint(w, " | ")
			}
			_, _ = fmt.Fprint(w, link)
		}
	}
	_, _ = fmt.Fprintln(w, "</p>")

	// Entry points.
	if len(entryPoints) > 0 {
		_, _ = fmt.Fprintln(w, "<h2>Entry Points</h2>")
		_, _ = fmt.Fprintf(w, "<p>%d functions with no incoming BL edges (roots of the call tree):</p>\n", len(entryPoints))
		_, _ = fmt.Fprintln(w, "<table>")
		_, _ = fmt.Fprintln(w, "<tr><th>Function</th></tr>")
		limit := 50
		if len(entryPoints) < limit {
			limit = len(entryPoints)
		}
		for _, ep := range entryPoints[:limit] {
			cfgLink := ""
			if cfgCount > 0 {
				safe := safeFuncNameHTML(ep)
				cfgLink = fmt.Sprintf(` <a href="cfg/%s.svg" style="font-size:11px">[cfg]</a>`, safe)
			}
			_, _ = fmt.Fprintf(w, "<tr><td class=\"ep\">%s%s</td></tr>\n", htmlEscape(ep), cfgLink)
		}
		if len(entryPoints) > limit {
			_, _ = fmt.Fprintf(w, "<tr><td>... and %d more</td></tr>\n", len(entryPoints)-limit)
		}
		_, _ = fmt.Fprintln(w, "</table>")
	}

	// Top classes by method count.
	if len(stats.TopOwners) > 0 {
		_, _ = fmt.Fprintln(w, "<h2>Top Classes</h2>")
		_, _ = fmt.Fprintln(w, "<table>")
		_, _ = fmt.Fprintln(w, "<tr><th>Class</th><th>Methods</th><th></th></tr>")
		limit := 20
		if len(stats.TopOwners) < limit {
			limit = len(stats.TopOwners)
		}
		maxCount := stats.TopOwners[0].Count
		for _, nc := range stats.TopOwners[:limit] {
			barW := nc.Count * 120 / maxCount
			if barW < 2 {
				barW = 2
			}
			_, _ = fmt.Fprintf(w, "<tr><td>%s</td><td class=\"num\">%d</td><td><span class=\"mbar\" style=\"width:%dpx\"></span></td></tr>\n",
				htmlEscape(stripOwnerHash(nc.Name)), nc.Count, barW)
		}
		_, _ = fmt.Fprintln(w, "</table>")
	}

	// Top callers.
	if len(stats.TopCallers) > 0 {
		_, _ = fmt.Fprintln(w, "<h2>Top Callers</h2>")
		_, _ = fmt.Fprintln(w, "<table>")
		_, _ = fmt.Fprintln(w, "<tr><th>Function</th><th>Outgoing</th></tr>")
		limit := 15
		if len(stats.TopCallers) < limit {
			limit = len(stats.TopCallers)
		}
		for _, nc := range stats.TopCallers[:limit] {
			_, _ = fmt.Fprintf(w, "<tr><td>%s</td><td class=\"num\">%d</td></tr>\n", htmlEscape(nc.Name), nc.Count)
		}
		_, _ = fmt.Fprintln(w, "</table>")
	}

	// Top callees.
	if len(stats.TopCallees) > 0 {
		_, _ = fmt.Fprintln(w, "<h2>Top Callees</h2>")
		_, _ = fmt.Fprintln(w, "<table>")
		_, _ = fmt.Fprintln(w, "<tr><th>Function</th><th>Incoming</th></tr>")
		limit := 15
		if len(stats.TopCallees) < limit {
			limit = len(stats.TopCallees)
		}
		for _, nc := range stats.TopCallees[:limit] {
			_, _ = fmt.Fprintf(w, "<tr><td>%s</td><td class=\"num\">%d</td></tr>\n", htmlEscape(nc.Name), nc.Count)
		}
		_, _ = fmt.Fprintln(w, "</table>")
	}

	// Unresolved THR summary.
	if len(unresTHR) > 0 {
		_, _ = fmt.Fprintln(w, "<h2>Unresolved THR Accesses</h2>")
		// Group by offset.
		type offInfo struct {
			offset string
			class  string
			count  int
		}
		offMap := make(map[string]*offInfo)
		for _, r := range unresTHR {
			if oi, ok := offMap[r.THROffset]; ok {
				oi.count++
			} else {
				offMap[r.THROffset] = &offInfo{r.THROffset, r.Class, 1}
			}
		}
		// Sort by offset for stable output.
		offSlice := make([]*offInfo, 0, len(offMap))
		for _, oi := range offMap {
			offSlice = append(offSlice, oi)
		}
		sort.Slice(offSlice, func(i, j int) bool {
			return offSlice[i].offset < offSlice[j].offset
		})
		_, _ = fmt.Fprintln(w, "<table>")
		_, _ = fmt.Fprintln(w, "<tr><th>Offset</th><th>Class</th><th>Count</th></tr>")
		for _, oi := range offSlice {
			_, _ = fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td class=\"num\">%d</td></tr>\n",
				htmlEscape(oi.offset), htmlEscape(oi.class), oi.count)
		}
		_, _ = fmt.Fprintln(w, "</table>")
	}

	_, _ = fmt.Fprintln(w, "</body></html>")
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// safeFuncNameHTML converts a function name to a safe filename.
// Must match sanitizeFilename in cmd/aotopsy/disasm.go.
func safeFuncNameHTML(name string) string {
	// P4-5: Use shared SanitizeFilename to match the canonical implementation.
	// Previously this had its own replacer that didn't strip non-printable
	// runes, causing broken asm links for names with special characters.
	return strutil.SanitizeFilename(name)
}
