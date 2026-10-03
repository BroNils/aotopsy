package render

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"aotopsy/internal/signal"
)

// gzipBase64 gzip-compresses data and returns the base64-encoded result.
// Failures propagate because an empty/partial blob makes the self-contained
// report look successfully written while the browser silently cannot load it.
func gzipBase64(data []byte) (string, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", fmt.Errorf("create gzip writer: %w", err)
	}
	if _, err := gz.Write(data); err != nil {
		_ = gz.Close()
		return "", fmt.Errorf("compress payload: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("finish compressed payload: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// WriteSignalHTML writes a self-contained HTML page for the signal graph.
// asmSnippets maps function name → first N lines of annotated disasm.
// asmLinks maps the same function name to the exact report-relative file that
// supplied that snippet; this keeps nested owner directories and legacy flat
// fallback files in sync with the link the browser opens.
func WriteSignalHTML(w io.Writer, g *signal.SignalGraph, title, filename, digest string, asmSnippets, asmLinks map[string]string) error {
	graph := signalGraphHTMLPayload(g)
	graphJSON, err := json.Marshal(graph)
	if err != nil {
		return fmt.Errorf("marshal signal graph: %w", err)
	}
	if asmSnippets == nil {
		asmSnippets = map[string]string{}
	}
	if asmLinks == nil {
		asmLinks = map[string]string{}
	}
	safeAsmLinks := make(map[string]string, len(asmLinks))
	for name, rel := range asmLinks {
		if href, ok := safeRelativeArtifactLink(rel); ok {
			safeAsmLinks[name] = href
		}
	}
	asmJSON, err := json.Marshal(asmSnippets)
	if err != nil {
		return fmt.Errorf("marshal asm snippets: %w", err)
	}
	asmLinksJSON, err := json.Marshal(safeAsmLinks)
	if err != nil {
		return fmt.Errorf("marshal asm links: %w", err)
	}
	gzGraph, err := gzipBase64(graphJSON)
	if err != nil {
		return fmt.Errorf("compress signal graph: %w", err)
	}
	gzAsm, err := gzipBase64(asmJSON)
	if err != nil {
		return fmt.Errorf("compress asm snippets: %w", err)
	}
	gzAsmLinks, err := gzipBase64(asmLinksJSON)
	if err != nil {
		return fmt.Errorf("compress asm links: %w", err)
	}
	ew := &errorWriter{w: w}
	w = ew

	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%s — Signal Graph</title>
<style>
:root {
  /* Surfaces */
  --bg: #000000; --bg2: #0a0a0a; --surface: #141414; --border: #222;
  /* Text hierarchy: bright > text > muted */
  --bright: #ffffff; --text: #c0c0c0; --muted: #808080;
  /* Semantic */
  --blue: #87CEEB; --pink: #FF80C0; --gold: #FFC800;
  --orange: #FF8000; --green: #00FF00; --red: #ff4444;
  /* Aliases */
  --link: var(--blue);
  /* Type scale: 3 sizes only */
  --fs: 14px; --fs-sm: 12px; --fs-xs: 10px;
  /* Spacing: 4px base unit */
  --sp-1: 4px; --sp-2: 8px; --sp-3: 16px; --sp-4: 24px;
  /* Font */
  --mono: "SF Mono","Fira Code","Consolas","Liberation Mono",monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--mono); font-size: var(--fs); line-height: 1.5; color: var(--text); background: var(--bg); padding: var(--sp-3) var(--sp-4); }
a { color: var(--link); text-decoration: none; }
a:hover { color: var(--bright); }

/* --- Page header --- */
h1 { font-size: var(--fs); font-weight: 600; color: var(--bright); margin-bottom: var(--sp-1); }
.file-info { font-size: var(--fs-sm); color: var(--muted); margin-bottom: var(--sp-3); }
.file-info .digest { margin-left: var(--sp-2); opacity: 0.6; }

/* --- Stats bar --- */
.stats { display: flex; gap: var(--sp-4); font-size: var(--fs-sm); color: var(--muted); margin-bottom: var(--sp-3); }
.stats b { color: var(--bright); font-weight: 400; }

/* --- Toolbar (search + scope + view) --- */
.toolbar { display: flex; gap: var(--sp-3); flex-wrap: wrap; align-items: center; margin-bottom: var(--sp-3); }
.search-box input { width: 480px; max-width: 100%%; padding: var(--sp-1) var(--sp-2); font: inherit; font-size: var(--fs-sm); border: 1px solid var(--border); background: var(--bg2); color: var(--text); border-radius: 3px; }
.search-box input:focus { outline: none; border-color: var(--link); }
.search-box input::placeholder { color: var(--muted); }
.btn { display: inline-block; padding: var(--sp-1) 10px; cursor: pointer; font: inherit; font-size: var(--fs-sm); border: 1px solid var(--border); background: var(--bg2); color: var(--muted); border-radius: 3px; }
.btn:hover { color: var(--text); background: var(--surface); }
.btn.active { color: var(--bright); background: var(--surface); border-color: var(--link); }
.btn-group { display: flex; gap: 1px; }

/* --- Category tags --- */
.cats-bar { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: var(--sp-2); }
.cat-tag { display: inline-block; padding: 2px 8px; font-size: var(--fs-xs); cursor: pointer; background: var(--surface); border-radius: 4px; border: 1px solid var(--border); }
.cat-tag:hover { border-color: var(--muted); }
.cat-tag.active { color: var(--bright); border-color: var(--bright); }
.cat-url { color: var(--blue); }
.cat-host { color: var(--orange); }
.cat-encryption { color: var(--red); }
.cat-auth { color: var(--pink); }
.cat-net { color: var(--green); }
.cat-file { color: var(--gold); }
.cat-base64 { color: var(--orange); }
.cat-thr { color: var(--blue); }
.cat-sim { color: var(--red); }
.cat-sms { color: var(--red); }
.cat-contacts { color: var(--pink); }
.cat-location { color: var(--orange); }
.cat-device { color: var(--gold); }
.cat-cloaking { color: var(--red); }
.cat-data { color: var(--pink); }
.cat-camera { color: var(--green); }
.cat-webview { color: var(--orange); }
.cat-blockchain { color: var(--gold); }
.cat-gambling { color: var(--red); }

/* --- Count --- */
#count { font-size: var(--fs-sm); color: var(--muted); margin-bottom: var(--sp-2); }

/* --- Class groups --- */
.class-group { margin-bottom: var(--sp-1); }
.class-header { padding: var(--sp-1) var(--sp-2); cursor: pointer; display: flex; align-items: center; gap: var(--sp-2); color: var(--gold); border-radius: 3px; }
.class-header:hover { background: var(--surface); }
.class-header .arrow { font-size: var(--fs-sm); transition: transform 0.15s; color: var(--muted); }
.class-group.collapsed .class-body { display: none; }
.class-group.collapsed .arrow { transform: rotate(-90deg); }
.class-count { font-size: var(--fs-sm); color: var(--muted); margin-left: auto; }

/* --- Function cards --- */
.card { margin-bottom: var(--sp-4); }
.card.context { opacity: 0.5; }
.card.other { opacity: 0.3; }
.card.revealed { opacity: 1 !important; background: rgba(255,200,0,0.05); }
.card-header { padding: var(--sp-1) 0; cursor: pointer; display: flex; align-items: center; gap: var(--sp-2); }
.card-header:hover .func-name { color: var(--bright); }
.func-name { color: var(--gold); word-break: break-all; }
.owner-name { font-size: var(--fs-sm); color: var(--muted); }
.sev-badge { font-size: var(--fs-sm); font-weight: 600; padding: 1px 6px; text-transform: uppercase; letter-spacing: 0.5px; border-radius: 3px; }
.sev-badge.high { background: rgba(241,76,76,0.15); color: var(--red); }
.sev-badge.medium { background: rgba(255,128,0,0.15); color: var(--orange); }
.sev-badge.ep { background: rgba(0,255,0,0.1); color: var(--green); }
.card-tags { display: flex; gap: var(--sp-1); flex-wrap: wrap; margin-left: auto; }
.asm-link { font-size: var(--fs-sm); color: var(--link); margin-left: 6px; opacity: 0.6; }
.asm-link:hover { opacity: 1; }
.card-body { display: none; padding: var(--sp-1) 0 var(--sp-2) 0; }
.card.open .card-body { display: block; }

/* --- String refs inside cards --- */
.str-ref { padding: 2px 0; word-break: break-all; line-height: 1.6; }
.str-val { color: var(--pink); }
.str-pc { font-size: var(--fs-sm); color: var(--muted); cursor: pointer; }
.str-pc:hover { color: var(--link); }

/* --- Content box (one class for all content blocks) --- */
.cbox { margin-bottom: var(--sp-2); color: var(--bright); }
.cbox .section-label { font-size: var(--fs-sm); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: var(--sp-1); position: relative; z-index: 2; }
.cbox.asm { line-height: 1.5; white-space: pre-wrap; word-break: break-all; max-height: 260px; overflow: hidden; cursor: pointer; position: relative; }
.cbox.asm::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 40px; background: linear-gradient(rgba(0,0,0,1), rgba(0,0,0,0.85) 40%%, rgba(0,0,0,0)); pointer-events: none; z-index: 1; }
.cbox.asm::after { content: ""; position: absolute; bottom: 0; left: 0; right: 0; height: 40px; background: linear-gradient(rgba(0,0,0,0), rgba(0,0,0,0.85) 60%%, rgba(0,0,0,1)); pointer-events: none; }
.cbox.asm.expanded { max-height: none; }
.cbox.asm.expanded::before, .cbox.asm.expanded::after { display: none; }
.neighbor-list { line-height: 1.8; display: flex; flex-wrap: wrap; gap: var(--sp-1) var(--sp-2); }
.neighbor-list a { color: var(--muted); }
.neighbor-list a:hover { color: var(--link); }
.neighbor-list a.nb-high { color: var(--red); }
.neighbor-list a.nb-med { color: var(--orange); }
.neighbor-list a.nb-sig { color: var(--link); }
.backtrace { line-height: 1.8; }
.backtrace-line { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.backtrace-line a { color: var(--muted); }
.backtrace-line a:hover { color: var(--link); }
.backtrace-line a.nb-high { color: var(--red); }
.backtrace-line a.nb-med { color: var(--orange); }
.backtrace-line a.nb-sig { color: var(--link); }
.bt-arrow { color: #646464; }
.a-addr { color: var(--gold); }
.a-bytes { color: var(--muted); }
.a-instr { color: var(--bright); }
.a-reg { color: var(--blue); }
.a-imm { color: var(--pink); }
.a-comment { color: var(--bright); }
.a-str { color: var(--pink); }
.a-pp { color: var(--blue); }
.a-thr { color: var(--pink); }
.a-name { color: var(--gold); }
.a-arrows { user-select: none; }
.hidden { display: none; }

/* --- Signals table (inside cards) --- */
.sig-table { border-collapse: collapse; }
.sig-table td { padding: 2px 12px 2px 0; vertical-align: top; line-height: 1.5; }
.sig-table .sig-pc { white-space: nowrap; vertical-align: top; }
.sig-table .sig-pc a { color: var(--gold); }
.sig-table .sig-pc a:hover { color: var(--bright); }
.sig-table .sig-pc .sig-cat { display: block; font-size: var(--fs-xs); line-height: 1.2; }
.sig-table .sig-val { color: var(--bright); word-break: break-all; }
.sig-table .sig-decoded { display: block; color: var(--muted); font-size: var(--fs-sm); margin-top: 1px; }

/* --- Strings view table --- */
.str-table { width: 100%%; border-collapse: collapse; }
.str-table th { text-align: left; padding: var(--sp-1) 10px; font-size: var(--fs-sm); font-weight: 400; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; position: sticky; top: 0; cursor: pointer; user-select: none; border-bottom: 1px solid var(--border); background: var(--bg); }
.str-table th:hover { color: var(--text); }
.str-table td { padding: var(--sp-1) 10px; border-bottom: 1px solid var(--border); vertical-align: top; line-height: 1.6; }
.str-table tr:hover { background: var(--surface); }
.str-table td.str-val-cell { color: var(--pink); word-break: break-all; max-width: 500px; }
.str-table td.str-func-cell { max-width: 300px; word-break: break-all; }
.str-table td.str-func-cell a { color: var(--gold); }
.str-table td.str-func-cell a:hover { color: var(--bright); }
.str-table td.str-cat-cell { white-space: nowrap; }
.str-table td.str-pc-cell { color: var(--gold); white-space: nowrap; }
.str-cat-row td { font-weight: 600; padding: var(--sp-3) 10px var(--sp-1) !important; border-bottom: none; color: var(--gold); }
</style>
</head>
<body>
<h1>%s</h1>
<div class="file-info">%s<span class="digest">%s</span> <a href="signal.svg">signal graph</a></div>
`, htmlEscape(title), htmlEscape(title), htmlEscape(filename), htmlEscape(digest))

	// Stats bar.
	_, _ = fmt.Fprintf(w, `<div class="stats">
<span><b>%d</b> signal</span>
	<span><b>%d</b> context</span>
	<span><b>%d</b> total</span>
	<span><b>%d</b> strings</span>
	<span><b>%d</b> call sites</span>
	<span><b>%d</b> static relations</span>
	<span><b>%d</b> incomplete poly</span>
	<span><b>%d</b> unknown candidate count</span>
		<span><b>%d</b> unresolved indirect</span>
		<span><b>%d</b> unsupported call kind</span>
		<span><b>%d</b> runtime-observed sites</span>
</div>
		`, graph.Stats.SignalFuncs, graph.Stats.ContextFuncs,
		graph.Stats.TotalFuncs,
		graph.Stats.StringRefCount, graph.Stats.CallSites, graph.Stats.StaticRelations,
		graph.Stats.IncompletePolymorphicSites, graph.Stats.UnknownCandidateCountSites, graph.Stats.UnresolvedIndirectSites,
		graph.Stats.UnsupportedCallSites, graph.Stats.RuntimeObservedSites)

	// Toolbar.
	_, _ = fmt.Fprint(w, `<div class="toolbar">
<div class="search-box"><input id="search" type="text" placeholder="Search functions or strings..." oninput="filterAll()"></div>
<div class="btn-group">
  <span class="btn role-signal active" onclick="setScope('signal')">Signal</span>
  <span class="btn role-context" onclick="setScope('context')">+Context</span>
  <span class="btn role-all" onclick="setScope('all')">All</span>
</div>
<div class="btn-group">
  <span class="btn active" data-view="class" onclick="setView('class')">By Class</span>
  <span class="btn" data-view="flat" onclick="setView('flat')">Flat</span>
  <span class="btn" data-view="strings" onclick="setView('strings')">Strings</span>
</div>
</div>
`)

	// Category filter bar.
	_, _ = fmt.Fprint(w, `<div class="cats-bar" id="catbar"></div>
<div id="count"></div>
`)

	// Boot log (terminal-style progress).
	_, _ = fmt.Fprint(w, `<div id="boot-log" style="font-size:var(--fs-sm);color:var(--muted);line-height:1.8;padding:var(--sp-2) 0;white-space:pre"></div>
`)

	// Cards container.
	_, _ = fmt.Fprint(w, `<div id="cards"></div>
`)

	// Embed gzip+base64 data blobs. Base64's alphabet cannot terminate the
	// script element, so the serialized attacker-controlled data never enters an
	// HTML/JavaScript source context before the runtime escaping layer sees it.
	_, _ = fmt.Fprintf(w, `<script>
	const _GZ_G = "%s";
	const _GZ_ASM = "%s";
	const _GZ_ASM_LINKS = "%s";
	`, gzGraph, gzAsm, gzAsmLinks)

	// JS logic: decompress blobs with progress, then run app.
	_, _ = fmt.Fprint(w, `
const _t0 = performance.now();
const _log = document.getElementById("boot-log");
function _emit(msg) {
  const t = ((performance.now() - _t0) / 1000).toFixed(1);
  _log.textContent += t + "s  " + msg + "\n";
}

async function _decompress(b64) {
  const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const ds = new DecompressionStream("gzip");
  const writer = ds.writable.getWriter();
  writer.write(bin);
  writer.close();
  const chunks = [];
  const reader = ds.readable.getReader();
  for (;;) {
    const {done, value} = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const blob = new Blob(chunks);
  return JSON.parse(await blob.text());
}

let G, ASM, ASM_LINKS;
(async () => {
  const _frame = () => new Promise(r => requestAnimationFrame(r));
  _emit("decompressing graph data (" + (_GZ_G.length / 1024 | 0) + " KB)..."); await _frame();
  G = await _decompress(_GZ_G);
  _emit("decompressing asm data (" + (_GZ_ASM.length / 1024 | 0) + " KB)..."); await _frame();
  ASM = Object.assign(Object.create(null), await _decompress(_GZ_ASM));
	ASM_LINKS = Object.assign(Object.create(null), await _decompress(_GZ_ASM_LINKS));
  _emit("loaded " + G.funcs.length + " functions, " + G.edges.length + " edges, " + Object.keys(ASM).length + " asm snippets"); await _frame();
  _emit("building indices..."); await _frame();
  _boot();
})();

function _boot() {
// Build name→index map before edge projection so external/runtime targets can
// be kept as evidence without becoming navigable static function relations.
const nameIdx = Object.create(null);
G.funcs.forEach((f, i) => { nameIdx[f.name] = i; });

// Build neighbor index from the known-endpoint STATIC projection. Sets avoid
// duplicate caller/callee rows when multiple call sites express one relation.
const callers = Object.create(null), callees = Object.create(null);
function staticResolution(r) {
  return r === "direct" || r === "monomorphic" || r === "polymorphic_candidate";
}
G.edges.forEach(e => {
  if (e.to && staticResolution(e.resolution) && nameIdx[e.to] !== undefined) {
    if (!callees[e.from]) callees[e.from] = new Set();
    callees[e.from].add(e.to);
    if (!callers[e.to]) callers[e.to] = new Set();
    callers[e.to].add(e.from);
  }
});
Object.keys(callers).forEach(k => { callers[k] = Array.from(callers[k]).sort(); });
Object.keys(callees).forEach(k => { callees[k] = Array.from(callees[k]).sort(); });

// Preserve non-traversable call-site semantics for each function card.
const callEvidence = Object.create(null);
const polyListed = Object.create(null);
G.edges.forEach(e => {
  if (e.resolution !== "polymorphic_candidate") return;
  const key = [e.from, e.from_pc || "", e.kind || "", e.via || ""].join("\u0000");
  polyListed[key] = (polyListed[key] || 0) + (e.to ? 1 : 0);
});
const evidenceSeen = Object.create(null);
function addEvidence(from, key, text) {
  const full = from + "\u0000" + key;
  if (evidenceSeen[full]) return;
  evidenceSeen[full] = true;
  if (!callEvidence[from]) callEvidence[from] = [];
  callEvidence[from].push(text);
}
G.edges.forEach(e => {
  const pc = e.from_pc || "unknown pc";
  const siteKey = [e.from, e.from_pc || "", e.kind || "", e.via || ""].join("\u0000");
  if (!staticResolution(e.resolution) && e.resolution !== "runtime_observed" &&
      e.resolution !== "unresolved" && e.resolution !== "address_only") {
    addEvidence(e.from, "schema\u0000" + siteKey + "\u0000" + (e.to || ""),
      "invalid/missing resolution @ " + pc);
    return;
  }
  if (e.resolution === "runtime_observed") {
    let text = "runtime observed: " + (e.to || "unknown target");
    if (e.runtime_observations) text += " ×" + e.runtime_observations;
    if (e.runtime_agreement) text += " (" + e.runtime_agreement + ")";
    addEvidence(e.from, "runtime\u0000" + siteKey + "\u0000" + (e.to || ""), text);
    return;
  }
  if (e.resolution === "unresolved") {
    addEvidence(e.from, "unresolved\u0000" + siteKey,
      "unresolved indirect @ " + pc + (e.via ? " via " + e.via : ""));
  } else if (e.resolution === "address_only") {
    addEvidence(e.from, "address\u0000" + siteKey,
      "direct address " + (e.target_address || "unknown") + " @ " + pc);
  } else if (e.to && nameIdx[e.to] === undefined) {
    addEvidence(e.from, "external\u0000" + siteKey + "\u0000" + e.to,
      "external static target: " + e.to + " @ " + pc);
  }
  if (e.resolution === "polymorphic_candidate" && !e.targets_complete) {
    const listed = polyListed[siteKey] || 0;
    if (e.candidate_count_known) {
      addEvidence(e.from, "poly\u0000" + siteKey,
        "candidate set incomplete @ " + pc + ": " + listed + " listed of " + e.candidate_count);
    } else {
      addEvidence(e.from, "poly\u0000" + siteKey,
        "candidate count unknown @ " + pc + ": " + listed + " listed");
    }
  }
});
Object.keys(callEvidence).forEach(k => callEvidence[k].sort());

let activeCat = null;
let scope = "signal"; // "signal", "context", "all"
let viewMode = "class";
const revealed = new Set(); // manually revealed function names

function catToken(c) { return String(c || "").replace(/[^a-zA-Z0-9_-]/g, "_"); }
function catClass(c) { return "cat-tag cat-" + catToken(c); }

function renderCatBar() {
  const bar = document.getElementById("catbar");
  const cats = Object.entries(G.stats.categories || {}).sort((a,b) => b[1]-a[1]);
  bar.innerHTML = cats.map(([c, n]) =>
    '<span class="' + esc(catClass(c)) + '" data-cat-action="' + esc(c) + '">' + esc(c) + '</span>'
  ).join("");
}

function toggleCat(c) {
  activeCat = activeCat === c ? null : c;
  document.querySelectorAll("#catbar .cat-tag").forEach(el => {
    el.classList.toggle("active", el.dataset.catAction === activeCat);
  });
  filterAll();
}

function setScope(s) {
  scope = s;
  document.querySelectorAll(".btn.role-signal,.btn.role-context,.btn.role-all").forEach(el => {
    el.classList.remove("active");
    if (s === "signal" && el.classList.contains("role-signal")) el.classList.add("active");
    if (s === "context" && el.classList.contains("role-context")) el.classList.add("active");
    if (s === "all" && el.classList.contains("role-all")) el.classList.add("active");
  });
  filterAll();
}

function setView(v) {
  viewMode = v;
  document.querySelectorAll(".btn[data-view]").forEach(el => {
    el.classList.toggle("active", el.dataset.view === v);
  });
  renderCards();
  filterAll();
}

function fmtName(name) {
  // Uppercase hex in sub_ names for consistency.
  if (/^sub_[0-9a-f]+$/.test(name)) return "sub_" + name.substring(4).toUpperCase();
  // Uppercase hex suffix after last underscore in named functions (e.g. "Foo.bar_1a2b3c").
  return name.replace(/_([0-9a-f]{4,})$/i, function(m, h) { return "_" + h.toUpperCase(); });
}

function neighborClass(name) {
  const idx = nameIdx[name];
  if (idx === undefined) return "";
  const f = G.funcs[idx];
  if (!f) return "";
  if (f.severity === "high") return " nb-high";
  if (f.severity === "medium") return " nb-med";
  if (f.role === "signal") return " nb-sig";
  return "";
}

function renderNeighborList(names) {
  if (names.length === 0) return "";
  return names.map(n =>
    '<a class="' + esc(neighborClass(n)) + '" href="#" data-reveal="' + esc(n) + '">' + esc(fmtName(n)) + '</a>'
  ).join("");
}

function renderTraceNode(n) {
  if (n.startsWith("...") || n.startsWith("[cycle] ")) {
    return '<span class="bt-arrow">' + esc(n) + '</span>';
  }
  return '<a class="' + esc(neighborClass(n)) + '" href="#" data-reveal="' + esc(n) + '">' + esc(fmtName(n)) + '</a>';
}

// Walk callers backwards up to maxDepth, return array of chains (each is an array of names, root first).
function getBacktraces(name, maxDepth) {
  const traces = [];
  function walk(cur, chain, visited) {
    const cls = callers[cur] || [];
    if (chain.length >= maxDepth || cls.length === 0) {
      traces.push(chain.slice());
      return;
    }
    // Limit fan-out: only follow first 3 callers per level to keep output bounded.
    const limit = Math.min(cls.length, 3);
    for (let i = 0; i < limit; i++) {
      const c = cls[i];
      if (visited.has(c)) {
        traces.push(["[cycle] " + c, ...chain]);
        continue;
      }
      visited.add(c);
      walk(c, [c, ...chain], visited);
      visited.delete(c);
    }
    if (cls.length > limit) {
      traces.push(["... +" + (cls.length - limit) + " more", ...chain]);
    }
  }
  const cls = callers[name] || [];
  if (cls.length === 0) return [];
  const visited = new Set([name]);
  const initialLimit = Math.min(cls.length, 3);
  for (let i = 0; i < initialLimit; i++) {
    const c = cls[i];
    visited.add(c);
    walk(c, [c], visited);
    visited.delete(c);
  }
  if (cls.length > initialLimit) traces.push(["... +" + (cls.length - initialLimit) + " more"]);
  return traces;
}

function renderBacktraces(name) {
  const traces = getBacktraces(name, 4);
  if (traces.length === 0) return "";
  // Separate single-node traces (no chain) from real chains.
  const singles = [];
  const chains = [];
  traces.forEach(chain => {
    if (chain.length <= 1) singles.push(chain[0] || "");
    else chains.push(chain);
  });
  let html = '<div class="backtrace">';
  // Render singles as a compact inline list.
  if (singles.length > 0) {
    html += '<div class="backtrace-line">';
    html += singles.map(renderTraceNode).join(', ');
    html += '</div>';
  }
  // Render chains as before, one per line.
  chains.forEach(chain => {
    html += '<div class="backtrace-line">';
    html += chain.map(renderTraceNode).join('<span class="bt-arrow"> \u2192 </span>');
    html += '</div>';
  });
  html += '</div>';
  return html;
}

function renderCard(f, i) {
  const cats = (f.categories || []).map(c => '<span class="' + esc(catClass(c)) + '">' + esc(c) + '</span>').join("");
  const role = f.role || "";
  const isSignal = role === "signal";
  let cls = "card";
  if (isSignal) cls += " open"; // signal cards expanded by default
  if (role === "context") cls += " context";
  if (role === "") cls += " other";
  let html = '<div class="' + cls + '" id="card-' + i + '" data-name="' + esc(f.name) + '" data-role="' + esc(role) + '" data-sev="' + esc(f.severity||"") + '" data-cats="' + esc((f.categories||[]).join(",")) + '" data-strings="' + esc((f.string_refs||[]).map(r=>r.value).join("|")) + '" data-owner="' + esc(f.owner||"") + '">';
  html += '<div class="card-header" onclick="toggle(' + i + ')">';
  if (f.is_root_candidate) html += '<span class="sev-badge ep">ROOT</span>';
  if (f.severity === "high") html += '<span class="sev-badge high">HIGH</span>';
  else if (f.severity === "medium") html += '<span class="sev-badge medium">MED</span>';
  html += '<span class="func-name">' + esc(fmtName(f.name)) + '</span>';
  if (ASM[f.name] && ASM_LINKS[f.name]) html += '<a class="asm-link" href="' + esc(ASM_LINKS[f.name]) + '" target="_blank" rel="noopener" onclick="event.stopPropagation()">asm</a>';
  if (f.owner) html += ' <span class="owner-name">' + esc(fmtName(f.owner)) + '</span>';
  html += '<div class="card-tags">' + cats + '</div>';
  html += '</div>';
  html += '<div class="card-body">';

  // 1. Signals (no title, before asm).
  if (f.string_refs && f.string_refs.length > 0) {
    const seen = Object.create(null);
    f.string_refs.forEach(r => {
      if (seen[r.value]) { seen[r.value].count++; return; }
      seen[r.value] = {r: r, count: 1};
    });
    const rows = Object.values(seen);
    html += '<div class="cbox"><table class="sig-table">';
    rows.forEach(({r, count}) => {
      const strCats = r.categories || [];
      const primary = strCats[0] || "";
      const colorCls = primary ? "cat-" + catToken(primary) : "";
      const pcDisp = r.pc.startsWith("0x") ? r.pc.substring(2).toUpperCase() : r.pc;
      html += '<tr>';
      html += '<td class="sig-pc"><a href="#" data-scroll-card="' + i + '" data-scroll-pc="' + esc(r.pc) + '">' + esc(pcDisp) + '</a>';
      if (primary) html += '<span class="sig-cat ' + esc(colorCls) + '">' + esc(primary) + '</span>';
      html += '</td>';
      html += '<td class="sig-val">"' + esc(r.value) + '"';
      if (count > 1) html += ' <span class="owner-name">\u00d7' + count + '</span>';
      if (strCats.includes("base64")) {
        try { const d = atob(r.value); if (d.length > 0 && /^[\x20-\x7e\r\n\t]+$/.test(d)) html += '<span class="sig-decoded">\u2192 ' + esc(d) + '</span>'; } catch(e) {}
      }
      html += '</td>';
      html += '</tr>';
    });
    html += '</table></div>';
  }

  // 2. ASM.
  if (ASM[f.name]) {
    html += '<div class="cbox asm" onclick="this.classList.toggle(\'expanded\')"><div class="section-label">Disasm</div>' + colorizeAsm(ASM[f.name]) + '</div>';
  }

  // 3. Callers + Callees (each in own box).
  const cl = callers[f.name] || [];
  const ce = callees[f.name] || [];
  if (cl.length > 0) {
    html += '<div class="cbox">';
    html += '<div class="section-label">' + (cl.length === 1 ? 'Caller' : 'Callers') + '</div>';
    html += renderBacktraces(f.name);
    html += '</div>';
  }
  if (ce.length > 0) {
    html += '<div class="cbox">';
    html += '<div class="section-label">' + (ce.length === 1 ? 'Callee' : 'Callees') + '</div>';
    html += '<div class="neighbor-list">' + renderNeighborList(ce) + '</div>';
    html += '</div>';
  }

  const evidence = callEvidence[f.name] || [];
  if (evidence.length > 0) {
    html += '<div class="cbox"><div class="section-label">Call-site evidence</div>';
    html += '<div class="neighbor-list">' + evidence.map(x => '<span>' + esc(x) + '</span>').join('') + '</div>';
    html += '</div>';
  }

  html += '</div></div>';
  return html;
}

// Build flat list of all string refs with func metadata for Strings view.
const allStringRefs = [];
G.funcs.forEach((f, i) => {
  if (!f.string_refs) return;
  f.string_refs.forEach(r => {
    const strCats = r.categories || f.categories || [];
    allStringRefs.push({
      value: r.value,
      pc: r.pc,
      poolIdx: r.pool_idx,
      funcName: f.name,
      funcIdx: i,
      owner: f.owner || "",
      role: f.role || "",
      severity: f.severity || "",
      categories: strCats
    });
  });
});

let stringSortCol = "cat";
let stringSortAsc = true;

function renderStrings() {
  const container = document.getElementById("cards");
  const q = document.getElementById("search").value.toLowerCase();

  // Filter strings.
  let filtered = allStringRefs.filter(s => {
    if (scope === "signal" && s.role !== "signal") return false;
    if (scope === "context" && s.role !== "signal" && s.role !== "context") return false;
    if (q && !s.value.toLowerCase().includes(q) && !s.funcName.toLowerCase().includes(q)) return false;
    if (activeCat && !s.categories.includes(activeCat)) return false;
    return true;
  });

  // Group by category.
  const catGroups = Object.create(null);
  const catOrder = [];
  filtered.forEach(s => {
    const cat = (s.categories && s.categories.length > 0) ? s.categories[0] : "(uncategorized)";
    if (!catGroups[cat]) { catGroups[cat] = []; catOrder.push(cat); }
    catGroups[cat].push(s);
  });
  const sevOrder = {"high": 0, "medium": 1, "low": 2, "": 3};
	const groupSeverity = items => items.reduce((best, item) => {
	  const rank = sevOrder[item.severity] ?? 3;
	  return Math.min(best, rank);
	}, 3);
  catOrder.sort((a, b) => {
	const sa = groupSeverity(catGroups[a]);
	const sb = groupSeverity(catGroups[b]);
    if (sa !== sb) return sa - sb;
	return a === b ? 0 : (a < b ? -1 : 1);
  });

  // Sort within each group.
  const cmp = (a, b) => {
    let va, vb;
    if (stringSortCol === "value") { va = a.value; vb = b.value; }
    else if (stringSortCol === "func") { va = a.funcName; vb = b.funcName; }
    else if (stringSortCol === "pc") { va = a.pc; vb = b.pc; }
    else { va = a.value; vb = b.value; }
    if (va < vb) return stringSortAsc ? -1 : 1;
    if (va > vb) return stringSortAsc ? 1 : -1;
    return 0;
  };
  for (const cat in catGroups) catGroups[cat].sort(cmp);

  if (filtered.length === 0) {
    container.innerHTML = '<div class="owner-name" style="padding:20px">No strings match the current filter.</div>';
    document.getElementById("count").textContent = "0 / " + allStringRefs.length + " strings shown";
    return;
  }

  // Single table, category headers as spanning rows.
  let html = '<table class="str-table"><thead><tr>';
  html += '<th onclick="sortStrings(\'pc\')" style="width:10%">Address' + sortArrow("pc") + '</th>';
  html += '<th onclick="sortStrings(\'value\')" style="width:52%">Value' + sortArrow("value") + '</th>';
  html += '<th onclick="sortStrings(\'func\')" style="width:38%">Function' + sortArrow("func") + '</th>';
  html += '</tr></thead><tbody>';

  catOrder.forEach(cat => {
    const items = catGroups[cat];
	html += '<tr class="str-cat-row"><td colspan="3"><span class="' + esc(catClass(cat)) + '">' + esc(cat) + '</span> <span class="owner-name">' + items.length + '</span></td></tr>';
    items.forEach(s => {
      const addr = s.pc.startsWith("0x") ? s.pc.substring(2).toUpperCase() : s.pc;
      html += '<tr>';
	  html += '<td class="str-pc-cell">' + esc(addr) + '</td>';
      html += '<td class="str-val-cell">"' + esc(s.value) + '"</td>';
	  html += '<td class="str-func-cell"><a href="#" data-view-reveal="' + esc(s.funcName) + '">' + esc(fmtName(s.funcName)) + '</a></td>';
      html += '</tr>';
    });
  });

  html += '</tbody></table>';
  container.innerHTML = html;
  document.getElementById("count").textContent = filtered.length + " / " + allStringRefs.length + " strings shown";
}

function sortArrow(col) {
  if (stringSortCol !== col) return "";
  return stringSortAsc ? " &#9650;" : " &#9660;";
}

function sortStrings(col) {
  if (stringSortCol === col) stringSortAsc = !stringSortAsc;
  else { stringSortCol = col; stringSortAsc = true; }
  renderStrings();
}

function renderCards() {
  const container = document.getElementById("cards");
  if (viewMode === "strings") {
    renderStrings();
    return;
  }
  if (viewMode === "flat") {
    let html = "";
    G.funcs.forEach((f, i) => { html += renderCard(f, i); });
    container.innerHTML = html;
  } else {
	const groups = Object.create(null);
    const order = [];
    G.funcs.forEach((f, i) => {
      const owner = f.owner || "(no class)";
      if (!groups[owner]) { groups[owner] = []; order.push(owner); }
      groups[owner].push({f, i});
    });
    let html = "";
    order.forEach(owner => {
      const items = groups[owner];
      // Start groups collapsed if they contain no signal funcs.
      const hasSignal = items.some(({f}) => f.role === "signal");
      const collapsed = hasSignal ? "" : " collapsed";
      html += '<div class="class-group' + collapsed + '" data-owner="' + esc(owner) + '">';
      html += '<div class="class-header" onclick="toggleGroup(this.parentNode)">';
      html += '<span class="arrow">&#9660;</span> ' + esc(fmtName(owner));
      html += '<span class="class-count">' + items.length + '</span>';
      html += '</div>';
      html += '<div class="class-body">';
      items.forEach(({f, i}) => { html += renderCard(f, i); });
      html += '</div></div>';
    });
    container.innerHTML = html;
  }
}

function toggleGroup(el) {
  el.classList.toggle("collapsed");
}

function toggle(i) {
  document.getElementById("card-" + i).classList.toggle("open");
}

function scrollAsm(cardIdx, pc) {
  const card = document.getElementById("card-" + cardIdx);
  if (!card) return;
  card.classList.add("open");
  const asm = card.querySelector(".cbox.asm");
  if (!asm) return;
  asm.classList.add("expanded");
  const text = asm.textContent;
  const lines = text.split("\n");
  const lineHeight = 15;
  for (let li = 0; li < lines.length; li++) {
    if (lines[li].includes(pc)) {
      asm.scrollTop = Math.max(0, li * lineHeight - 60);
      const pre = asm.innerHTML;
      const escaped = esc(lines[li]);
      asm.innerHTML = pre.replace(escaped, '<span style="background:rgba(255,200,0,0.15)">' + escaped + '</span>');
      setTimeout(() => { asm.innerHTML = pre; }, 2000);
      return;
    }
  }
}

// Reveal a function (even if filtered out) and scroll to it.
function revealAndScroll(name) {
  revealed.add(name);
  const idx = nameIdx[name];
  if (idx === undefined) return;
  const card = document.getElementById("card-" + idx);
  if (!card) return;
  // Unhide card and parent group.
  card.classList.remove("hidden");
  card.classList.add("open", "revealed");
  const group = card.closest(".class-group");
  if (group) {
    group.classList.remove("collapsed", "hidden");
  }
  card.scrollIntoView({behavior: "smooth", block: "center"});
  setTimeout(() => card.classList.remove("revealed"), 3000);
}

function matchesFilter(c) {
  const q = document.getElementById("search").value.toLowerCase();
  const name = c.dataset.name.toLowerCase();
  const strings = (c.dataset.strings || "").toLowerCase();
  const idx = nameIdx[c.dataset.name];
  const categories = idx === undefined ? [] : (G.funcs[idx].categories || []);
  const role = c.dataset.role || "";

  // Scope filter: signal = signal only, context = signal+context, all = everything.
  // Revealed functions always pass.
  if (!revealed.has(c.dataset.name)) {
    if (scope === "signal" && role !== "signal") return false;
    if (scope === "context" && role !== "signal" && role !== "context") return false;
  }

  // Text search.
  if (q && !name.includes(q) && !strings.includes(q)) return false;

  // Category filter.
  if (activeCat && !categories.includes(activeCat)) return false;

  return true;
}

function filterAll() {
  if (viewMode === "strings") {
    renderStrings();
    return;
  }
  const cards = document.querySelectorAll(".card");
  let shown = 0;
  cards.forEach(c => {
    const vis = matchesFilter(c);
    c.classList.toggle("hidden", !vis);
    if (vis) shown++;
  });
  // Update group counts and hide empty groups.
  document.querySelectorAll(".class-group").forEach(g => {
    const visible = g.querySelectorAll(".card:not(.hidden)").length;
    const countEl = g.querySelector(".class-count");
    if (countEl) countEl.textContent = visible;
    g.classList.toggle("hidden", visible === 0);
  });
  document.getElementById("count").textContent = shown + " / " + cards.length + " functions";
}

function esc(s) {
  if (!s) return "";
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

document.addEventListener("click", ev => {
  const target = ev.target instanceof Element ? ev.target : null;
  if (!target) return;
  const cat = target.closest("[data-cat-action]");
  if (cat) {
    ev.preventDefault();
    toggleCat(cat.dataset.catAction || "");
    return;
  }
  const viewReveal = target.closest("[data-view-reveal]");
  if (viewReveal) {
    ev.preventDefault();
    const name = viewReveal.dataset.viewReveal || "";
    setView("class");
    revealAndScroll(name);
    return;
  }
  const reveal = target.closest("[data-reveal]");
  if (reveal) {
    ev.preventDefault();
    revealAndScroll(reveal.dataset.reveal || "");
    return;
  }
  const asmPC = target.closest("[data-scroll-card][data-scroll-pc]");
  if (asmPC) {
    ev.preventDefault();
    const idx = Number.parseInt(asmPC.dataset.scrollCard || "", 10);
    if (Number.isInteger(idx)) scrollAsm(idx, asmPC.dataset.scrollPc || "");
  }
});

function colorizeLine(s) {
  const m = s.match(/^(0x[0-9a-fA-F]+)(  )([0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2})(  )(.*)$/);
  if (!m) return s;
  const addr = '<span class="a-addr">' + m[1].substring(2).replace(/^0+/, "").toUpperCase() + '</span>';
  const bytes = '<span class="a-bytes">' + m[3].replace(/ /g, "").toUpperCase() + '</span>';
  let rest = m[5];
  // Split instruction from comment at first ";"
  let instr = rest, comment = "";
  const ci = rest.indexOf(";");
  if (ci >= 0) { instr = rest.substring(0, ci); comment = rest.substring(ci); }
  // Pad instruction to fixed column so annotations align.
  const instrPlain = instr.replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&quot;/g,'"');
  const padLen = 32;
  const pad = instrPlain.length < padLen ? " ".repeat(padLen - instrPlain.length) : " ";
  instr = instr.replace(/\b(X[0-9]{1,2}|W[0-9]{1,2}|SP|X30|XZR|WZR|X29|X28|X27|X26|X15)\b/g, '<span class="a-reg">$1</span>');
  instr = instr.replace(/(#-?0x[0-9a-fA-F]+|#-?[0-9]+)\b/g, '<span class="a-imm">$1</span>');
  instr = '<span class="a-instr">' + instr + '</span>';
  if (comment) {
    comment = comment.replace(/(&quot;[^&]*?&quot;)/g, '<span class="a-str">$1</span>');
    comment = comment.replace(/(PP\[\d+\])/g, '<span class="a-pp">$1</span>');
    comment = comment.replace(/(THR\.[a-zA-Z_]+)/g, '<span class="a-thr">$1</span>');
    comment = comment.replace(/(&lt;[^&]+?&gt;)/g, '<span class="a-name">$1</span>');
    comment = '<span class="a-comment">' + comment + '</span>';
  }
  return addr + m[2] + bytes + m[4] + instr + (comment ? pad + comment : "");
}

const arrowColors = ["#444", "#555", "#666", "#777"];

function colorizeAsm(raw) {
  const lines = raw.split("\n");
  // Pass 1: parse addresses.
  const addrs = [];
	const addrToIdx = Object.create(null);
  lines.forEach((line, i) => {
    const m = line.match(/^(0x[0-9a-fA-F]+)/);
    const a = m ? parseInt(m[1], 16) : null;
    addrs.push(a);
    if (a !== null) addrToIdx[a] = i;
  });
  // Pass 2: detect intra-function branches (B/B.cond/CBZ/CBNZ/TBZ/TBNZ, NOT BL/BLR).
  const branches = [];
  lines.forEach((line, i) => {
    if (addrs[i] === null) return;
    // Extract instruction after "0xADDR  HH HH HH HH  "
    const parts = line.match(/^0x[0-9a-fA-F]+  [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2}  (.+)$/);
    if (!parts) return;
    const inst = parts[1].split(";")[0].trim();
    // Match branch but NOT BL/BLR (function calls).
    if (/^BL[R ]?\b/.test(inst)) return;
    if (!/^(B|B\.\w+|CBZ|CBNZ|TBZ|TBNZ)\b/.test(inst)) return;
    const tm = inst.match(/\.\+(0x[0-9a-fA-F]+)/);
    if (!tm) return;
    const off = parseInt(tm[1], 16);
    // Skip huge offsets (inter-function, wrapping negative).
    if (off > 0x10000) return;
    const target = addrs[i] + off;
    if (addrToIdx[target] !== undefined) {
      branches.push({ from: i, to: addrToIdx[target] });
    }
  });
  if (branches.length === 0) {
    return lines.map(l => colorizeLine(esc(l))).join("\n");
  }
  // Assign columns (greedy non-overlapping, shorter spans first).
  branches.sort((a, b) => Math.abs(a.to - a.from) - Math.abs(b.to - b.from));
  const maxCols = 4;
  branches.forEach(br => {
    const lo = Math.min(br.from, br.to), hi = Math.max(br.from, br.to);
    for (let c = 0; c < maxCols; c++) {
      const ok = branches.every(o => {
        if (o === br || o.col === undefined || o.col !== c) return true;
        const oLo = Math.min(o.from, o.to), oHi = Math.max(o.from, o.to);
        return hi < oLo || lo > oHi;
      });
      if (ok) { br.col = c; break; }
    }
    if (br.col === undefined) br.col = 0;
  });
  const totalCols = Math.max(...branches.map(b => b.col)) + 1;
  // Build margin grid.
  const grid = lines.map(() => new Array(totalCols).fill(" "));
  const gridColor = lines.map(() => new Array(totalCols).fill(0));
  branches.forEach((br, bi) => {
    const lo = Math.min(br.from, br.to), hi = Math.max(br.from, br.to);
    const c = br.col;
    for (let i = lo; i <= hi; i++) { grid[i][c] = "\u2502"; gridColor[i][c] = c; }
    if (br.from < br.to) { grid[br.from][c] = "\u252c"; grid[br.to][c] = "\u2514"; }
    else { grid[br.from][c] = "\u2534"; grid[br.to][c] = "\u250c"; }
  });
  // Render.
  return lines.map((line, i) => {
    let margin = "";
    for (let c = 0; c < totalCols; c++) {
      const ch = grid[i][c];
      const color = arrowColors[gridColor[i][c] % arrowColors.length];
      if (ch !== " ") margin += '<span style="color:' + color + '">' + ch + '</span>';
      else margin += " ";
    }
    return '<span class="a-arrows">' + margin + '</span>' + colorizeLine(esc(line));
  }).join("\n");
}

// Expose handlers for inline onclick attributes.
window.setScope = setScope;
window.setView = setView;
window.toggleCat = toggleCat;
window.toggle = toggle;
window.toggleGroup = toggleGroup;
window.filterAll = filterAll;
window.scrollAsm = scrollAsm;
window.revealAndScroll = revealAndScroll;
window.sortStrings = sortStrings;

_emit("rendering " + G.funcs.length + " cards...");
renderCatBar();
renderCards();
filterAll();
_emit("ready.");
_log.style.transition = "opacity 2s";
setTimeout(() => { _log.style.opacity = "0"; setTimeout(() => _log.remove(), 2000); }, 3000);
} // end _boot
</script>
</body>
</html>
`)
	return ew.err
}

func signalGraphHTMLPayload(g *signal.SignalGraph) signal.SignalGraph {
	var graph signal.SignalGraph
	if g != nil {
		graph = *g
	}
	if graph.Funcs == nil {
		graph.Funcs = []signal.SignalFunc{}
	}
	graph.Edges = signalRenderableEdges(&graph)
	if graph.Edges == nil {
		graph.Edges = []signal.SignalEdge{}
	}
	if graph.Stats.Categories == nil {
		graph.Stats.Categories = map[string]int{}
	}
	return graph
}
