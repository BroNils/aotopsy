package analysis

import (
	"slices"
	"sort"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/naming"
)

// PlatformChannelRecord represents one detected Flutter platform channel endpoint.
type PlatformChannelRecord struct {
	ChannelName  string   `json:"channel_name"`
	ChannelTypes []string `json:"channel_types"` // method_channel, event_channel, basic_message_channel
	CallSites    []string `json:"call_sites"`
	Confidence   string   `json:"confidence"`
}

// BuildPlatformChannels joins three independent facts instead of guessing from
// string spelling: a channel-looking string exists, a function references that
// exact string, and the same function calls a Flutter channel API. Only joined
// records are emitted; a reverse-domain string by itself is not proof that it is
// a platform channel.
func BuildPlatformChannels(cl *cluster.Result, pl *naming.PoolLookups, funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord, stringRefs []disasm.StringRefRecord) []PlatformChannelRecord {
	if cl == nil || pl == nil {
		return nil
	}

	channelMap := make(map[string]*PlatformChannelRecord)
	getOrCreate := func(name string) *PlatformChannelRecord {
		if rec, ok := channelMap[name]; ok {
			return rec
		}
		rec := &PlatformChannelRecord{ChannelName: name, Confidence: "medium"}
		channelMap[name] = rec
		return rec
	}

	// 1. Scan pool strings for candidate channel names.
	// Platform channel names typically follow reverse-domain or slash-delimited naming:
	// e.g. "plugins.flutter.io/battery", "com.app.auth/payment", "flutter/lifecycle"
	for _, pe := range cl.Pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		if str, ok := pl.StringForRef(pe.RefID); ok && isCandidateChannelName(str) {
			getOrCreate(str)
		}
	}
	for _, sr := range stringRefs {
		if isCandidateChannelName(sr.Value) {
			getOrCreate(sr.Value)
		}
	}

	// Function -> candidate channel strings that function actually references.
	funcChannels := make(map[string]map[string]bool)
	for _, sr := range stringRefs {
		if _, ok := channelMap[sr.Value]; !ok || sr.Func == "" {
			continue
		}
		if funcChannels[sr.Func] == nil {
			funcChannels[sr.Func] = make(map[string]bool)
		}
		funcChannels[sr.Func][sr.Value] = true
	}

	// Bind those strings to concrete channel API calls from the same function.
	// Direct calls whose recovered symbolic identity is absent are resolved from
	// their exact TargetAddress only when functions.jsonl proves that PC.
	namesByPC := functionNamesByPC(funcs)
	for _, edge := range edges {
		channels := funcChannels[edge.FromFunc]
		if len(channels) == 0 {
			continue
		}
		for _, target := range resolvedFunctionTargets(edge, namesByPC) {
			chType := platformChannelTypeFromTarget(target)
			if chType == "" {
				continue
			}
			for chName := range channels {
				rec := channelMap[chName]
				rec.ChannelTypes = append(rec.ChannelTypes, chType)
				rec.CallSites = append(rec.CallSites, edge.FromFunc)
			}
		}
	}

	var results []PlatformChannelRecord
	for _, rec := range channelMap {
		if len(rec.ChannelTypes) == 0 {
			continue
		}
		slices.Sort(rec.ChannelTypes)
		rec.ChannelTypes = slices.Compact(rec.ChannelTypes)
		slices.Sort(rec.CallSites)
		rec.CallSites = slices.Compact(rec.CallSites)
		results = append(results, *rec)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ChannelName < results[j].ChannelName
	})

	return results
}

func platformChannelTypeFromTarget(target string) string {
	switch {
	case strings.Contains(target, "BasicMessageChannel"):
		return "basic_message_channel"
	case strings.Contains(target, "EventChannel"):
		return "event_channel"
	case strings.Contains(target, "MethodChannel"):
		return "method_channel"
	default:
		return ""
	}
}

func isCandidateChannelName(s string) bool {
	if len(s) < 4 || len(s) > 120 {
		return false
	}
	if strings.HasPrefix(s, "flutter/") || strings.HasPrefix(s, "plugins.flutter.io/") || strings.HasPrefix(s, "dev.flutter.pigeon.") {
		return true
	}
	// Reverse domain with slash (e.g. "com.example.app/channel")
	if (strings.HasPrefix(s, "com.") || strings.HasPrefix(s, "io.") || strings.HasPrefix(s, "net.") || strings.HasPrefix(s, "org.")) && strings.Contains(s, "/") {
		return true
	}
	return false
}
