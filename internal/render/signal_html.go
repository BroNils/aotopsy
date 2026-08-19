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
// If gzip fails (theoretically unreachable: gzip.NewWriterLevel with
// BestCompression never fails, and bytes.Buffer never fails on Write/Close),
// returns empty string rather than uncompressed base64 — the JS client
// always uses DecompressionStream("gzip"), so uncompressed data would
// fail to decompress client-side, causing silent data loss.
func gzipBase64(data []byte) string {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return ""
	}
	if _, err := gz.Write(data); err != nil {
		return ""
	}
	if err := gz.Close(); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// WriteSignalHTML writes a self-contained HTML page for the signal graph.
// asmSnippets maps function name → first N lines of annotated disasm.
func WriteSignalHTML(w io.Writer, g *signal.SignalGraph, title, filename, digest string, asmSnippets map[string]string) {
	graphJSON, err := json.Marshal(g)
	if err != nil {
		_, _ = fmt.Fprintf(w, "<html><body>error marshaling signal graph: %v</body></html>", err)
		return
	}

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
<span><b>%d</b> edges</span>
</div>
`, g.Stats.SignalFuncs, g.Stats.ContextFuncs,
		g.Stats.TotalFuncs,
		g.Stats.StringRefCount, g.Stats.TotalEdges)

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

	// Embed gzip+base64 data blobs.
	asmJSON, _ := json.Marshal(asmSnippets)
	gzGraph := gzipBase64(graphJSON)
	gzAsm := gzipBase64(asmJSON)
	_, _ = fmt.Fprintf(w, `<script>
const _GZ_G = "%s";
const _GZ_ASM = "%s";
`, gzGraph, gzAsm)

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

let G, ASM;
(async () => {
  const _frame = () => new Promise(r => requestAnimationFrame(r));
  _emit("decompressing graph data (" + (_GZ_G.length / 1024 | 0) + " KB)..."); await _frame();
  G = await _decompress(_GZ_G);
  _emit("decompressing asm data (" + (_GZ_ASM.length / 1024 | 0) + " KB)..."); await _frame();
  ASM = await _decompress(_GZ_ASM);
  _emit("loaded " + G.funcs.length + " functions, " + G.edges.length + " edges, " + Object.keys(ASM).length + " asm snippets"); await _frame();
  _emit("building indices..."); await _frame();
  _boot();
})();

function _boot() {
// Build neighbor index from ALL edges.
const callers = {}, callees = {};
G.edges.forEach(e => {
  if ((e.kind === "bl" || e.kind === "call") && e.to) {
    if (!callees[e.from]) callees[e.from] = [];
    callees[e.from].push(e.to);
    if (!callers[e.to]) callers[e.to] = [];
    callers[e.to].push(e.from);
  }
});

// Build name→index map for fast lookup.
const nameIdx = {};
G.funcs.forEach((f, i) => { nameIdx[f.name] = i; });

let activeCat = null;
let scope = "signal"; // "signal", "context", "all"
let viewMode = "class";
const revealed = new Set(); // manually revealed function names

function catClass(c) { return "cat-tag cat-" + c; }

function renderCatBar() {
  const bar = document.getElementById("catbar");
  const cats = Object.entries(G.stats.categories || {}).sort((a,b) => b[1]-a[1]);
  bar.innerHTML = cats.map(([c, n]) =>
    '<span class="' + catClass(c) + '" data-cat="' + c + '" onclick="toggleCat(\'' + c + '\')">' + c + '</span>'
  ).join("");
}

function toggleCat(c) {
  activeCat = activeCat === c ? null : c;
  document.querySelectorAll("#catbar .cat-tag").forEach(el => {
    el.classList.toggle("active", el.dataset.cat === activeCat);
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
    '<a class="' + neighborClass(n) + '" href="#" onclick="revealAndScroll(\'' + esc(n) + '\');return false">' + esc(fmtName(n)) + '</a>'
  ).join("");
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
        traces.push([c + " (cycle)", ...chain]);
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
  cls.forEach(c => {
    visited.add(c);
    walk(c, [c], visited);
    visited.delete(c);
  });
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
    html += singles.map(n => {
      return '<a class="' + neighborClass(n) + '" href="#" onclick="revealAndScroll(\'' + esc(n) + '\');return false">' + esc(fmtName(n)) + '</a>';
    }).join(', ');
    html += '</div>';
  }
  // Render chains as before, one per line.
  chains.forEach(chain => {
    html += '<div class="backtrace-line">';
    html += chain.map(n => {
      if (n.startsWith("...")) return '<span class="bt-arrow">' + esc(n) + '</span>';
      return '<a class="' + neighborClass(n) + '" href="#" onclick="revealAndScroll(\'' + esc(n) + '\');return false">' + esc(fmtName(n)) + '</a>';
    }).join('<span class="bt-arrow"> \u2192 </span>');
    html += '</div>';
  });
  html += '</div>';
  return html;
}

function renderCard(f, i) {
  const cats = (f.categories || []).map(c => '<span class="' + catClass(c) + '">' + c + '</span>').join("");
  const role = f.role || "";
  const isSignal = role === "signal";
  let cls = "card";
  if (isSignal) cls += " open"; // signal cards expanded by default
  if (role === "context") cls += " context";
  if (role === "") cls += " other";
  let html = '<div class="' + cls + '" id="card-' + i + '" data-name="' + esc(f.name) + '" data-role="' + role + '" data-sev="' + (f.severity||"") + '" data-cats="' + (f.categories||[]).join(",") + '" data-strings="' + esc((f.string_refs||[]).map(r=>r.value).join("|")) + '" data-owner="' + esc(f.owner||"") + '">';
  html += '<div class="card-header" onclick="toggle(' + i + ')">';
  if (f.is_entry_point) html += '<span class="sev-badge ep">EP</span>';
  if (f.severity === "high") html += '<span class="sev-badge high">HIGH</span>';
  else if (f.severity === "medium") html += '<span class="sev-badge medium">MED</span>';
  html += '<span class="func-name">' + esc(fmtName(f.name)) + '</span>';
  if (ASM[f.name]) html += '<a class="asm-link" href="asm/' + encodeURIComponent(f.name) + '.txt" target="_blank" onclick="event.stopPropagation()">asm</a>';
  if (f.owner) html += ' <span class="owner-name">' + esc(fmtName(f.owner)) + '</span>';
  html += '<div class="card-tags">' + cats + '</div>';
  html += '</div>';
  html += '<div class="card-body">';

  // 1. Signals (no title, before asm).
  if (f.string_refs && f.string_refs.length > 0) {
    const seen = {};
    f.string_refs.forEach(r => {
      if (seen[r.value]) { seen[r.value].count++; return; }
      seen[r.value] = {r: r, count: 1};
    });
    const rows = Object.values(seen);
    html += '<div class="cbox"><table class="sig-table">';
    rows.forEach(({r, count}) => {
      const strCats = r.categories || [];
      const primary = strCats[0] || "";
      const colorCls = primary ? "cat-" + primary : "";
      const pcDisp = r.pc.startsWith("0x") ? r.pc.substring(2).toUpperCase() : r.pc;
      html += '<tr>';
      html += '<td class="sig-pc"><a href="#" onclick="scrollAsm(' + i + ',\'' + r.pc + '\');return false">' + pcDisp + '</a>';
      if (primary) html += '<span class="sig-cat ' + colorCls + '">' + primary + '</span>';
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
  const catGroups = {};
  const catOrder = [];
  filtered.forEach(s => {
    const cat = (s.categories && s.categories.length > 0) ? s.categories[0] : "(uncategorized)";
    if (!catGroups[cat]) { catGroups[cat] = []; catOrder.push(cat); }
    catGroups[cat].push(s);
  });
  const sevOrder = {"high": 0, "medium": 1, "low": 2, "": 3};
  catOrder.sort((a, b) => {
    const sa = catGroups[a][0] ? (sevOrder[catGroups[a][0].severity] || 3) : 3;
    const sb = catGroups[b][0] ? (sevOrder[catGroups[b][0].severity] || 3) : 3;
    if (sa !== sb) return sa - sb;
    return a < b ? -1 : 1;
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
    html += '<tr class="str-cat-row"><td colspan="3"><span class="' + catClass(cat) + '">' + cat + '</span> <span class="owner-name">' + items.length + '</span></td></tr>';
    items.forEach(s => {
      const addr = s.pc.startsWith("0x") ? s.pc.substring(2).toUpperCase() : s.pc;
      html += '<tr>';
      html += '<td class="str-pc-cell">' + addr + '</td>';
      html += '<td class="str-val-cell">"' + esc(s.value) + '"</td>';
      html += '<td class="str-func-cell"><a href="#" onclick="setView(\'class\');revealAndScroll(\'' + esc(s.funcName) + '\');return false">' + esc(fmtName(s.funcName)) + '</a></td>';
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
    const groups = {};
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
  const cats = c.dataset.cats || "";
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
  if (activeCat && !cats.includes(activeCat)) return false;

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
  const addrToIdx = {};
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
}
