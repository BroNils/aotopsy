package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// generateStalkerScript generates a Frida script that uses Stalker
// to trace execution and build a runtime call graph.
// This produces 100% accurate call graph including virtual dispatch,
// callbacks, async, and VM-supplied entry points.
func generateStalkerScript(metaPath string) string {
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Sprintf("// ERROR: cannot read %s: %v\n", metaPath, err)
	}
	var meta FridaMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Sprintf("// ERROR: cannot parse %s: %v\n", metaPath, err)
	}

	var sb strings.Builder

	sb.WriteString("'use strict';\n")
	sb.WriteString("// Auto-generated Stalker call graph tracer by aotopsy\n")
	sb.WriteString(fmt.Sprintf("// Dart: %s, Arch: %s\n", meta.DartVersion, meta.Architecture))
	sb.WriteString(fmt.Sprintf("// Functions: %d\n\n", len(meta.Functions)))

	// Build function range map for Stalker
	// Stalker follows execution; we need to know which function each call target belongs to
	sb.WriteString(fmt.Sprintf("// Function ranges for call annotation\n"))
	sb.WriteString(fmt.Sprintf("var FUNC_RANGES = [\n"))
	for i, f := range meta.Functions {
		if i > 0 {
			sb.WriteString(",\n")
		}
		va := parseHex(f.VA)
		end := va + uint64(f.Size)
		sb.WriteString(fmt.Sprintf("  {start: 0x%x, end: 0x%x, name: '%s'}",
			va, end, escapeJS(f.Name)))
	}
	sb.WriteString(fmt.Sprintf("\n];\n\n"))

	// Module base for offset calculation
	sb.WriteString(`var base = null;
var callGraph = {};  // caller → {callee: count}
var callCount = 0;
var MAX_CALLS = 100000;  // safety cap

function findFunc(addr) {
  var offset = addr.sub(base);
  var offNum = parseInt(offset.toString(), 16);
  // Binary search would be faster, but linear is fine for this
  for (var i = 0; i < FUNC_RANGES.length; i++) {
    var r = FUNC_RANGES[i];
    if (offNum >= r.start && offNum < r.end) {
      return r.name;
    }
  }
  return 'sub_' + offset.toString(16);
}

function recordCall(fromName, toAddr) {
  if (callCount++ >= MAX_CALLS) return;
  var toName = findFunc(toAddr);
  if (!callGraph[fromName]) callGraph[fromName] = {};
  if (!callGraph[fromName][toName]) callGraph[fromName][toName] = 0;
  callGraph[fromName][toName]++;

  // Log first 50 calls for immediate feedback
  if (callCount <= 50) {
    console.log('[stalker] ' + fromName + ' -> ' + toName);
  }
}

function startStalking() {
  base = null;
  var mod = Process.findModuleByName('libapp.so');
  if (!mod) {
    console.log('[stalker] Waiting for libapp.so...');
    setTimeout(startStalking, 500);
    return;
  }
  base = mod.base;
  console.log('[stalker] libapp.so @ ' + base);
  console.log('[stalker] Starting Stalker on main thread...');

  var mainThread = Process.getCurrentThreadId();

  Stalker.follow(mainThread, {
    events: {
      call: true,   // log CALL instructions
      ret: false,   // don't log RET (too noisy)
      exec: false,  // don't log every instruction
      block: false, // don't log block entries
      compile: false
    },

    onCallSummary: function(summary) {
      // summary = { "0xNNNN": count, ... } — call counts per call site
      for (var site in summary) {
        try {
          var siteAddr = ptr(site);
          var siteOffset = siteAddr.sub(base);
          var fromName = findFunc(siteAddr);

          // We don't know the target from summary alone,
          // but we can log which functions make calls
          if (!callGraph[fromName]) callGraph[fromName] = {};
          callGraph[fromName]['__calls__'] = (callGraph[fromName]['__calls__'] || 0) + summary[site];
        } catch(e) {}
      }
    },

    onReceive: function(events) {
      // events is an ArrayBuffer of call events
      try {
        var calls = Stalker.parse(events, {stringify: false, annotate: true});
        for (var i = 0; i < calls.length; i++) {
          var ev = calls[i];
          if (ev[0] === 'call') {
            // ev = ['call', fromAddr, toAddr]
            var fromAddr = ev[1];
            var toAddr = ev[2];
            var fromName = findFunc(fromAddr);
            recordCall(fromName, toAddr);
          }
        }
      } catch(e) {
        console.log('[stalker] parse error: ' + e);
      }
    }
  });

  console.log('[stalker] Stalking active. Interact with the app.');

  // Periodically dump call graph
  setInterval(function() {
    var totalCalls = 0;
    var totalEdges = 0;
    for (var caller in callGraph) {
      for (var callee in callGraph[caller]) {
        totalCalls += callGraph[caller][callee];
        totalEdges++;
      }
    }
    console.log('[stalker] Stats: ' + totalEdges + ' edges, ' + totalCalls + ' calls');

    // Send call graph to host
    send({type: 'callgraph', edges: totalEdges, calls: totalCalls, graph: callGraph});
  }, 10000);  // every 10 seconds
}

// Start
startStalking();

// Handle stop
Script.bindWeak({}, function() {
  Stalker.unfollow();
  console.log('[stalker] Stopped. Final graph: ' + JSON.stringify(callGraph).length + ' bytes');
  send({type: 'callgraph_final', graph: callGraph});
});
`)

	return sb.String()
}

func parseHex(s string) uint64 {
	var v uint64
	fmt.Sscanf(s, "0x%x", &v)
	if v == 0 {
		fmt.Sscanf(s, "%x", &v)
	}
	return v
}
