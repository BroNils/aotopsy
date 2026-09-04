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
	ChannelName string   `json:"channel_name"`
	ChannelType string   `json:"channel_type"` // "method_channel", "event_channel", "basic_message_channel"
	Methods     []string `json:"methods,omitempty"`
	Handlers    []string `json:"handlers,omitempty"`
	CallSites   []string `json:"call_sites,omitempty"`
}

// BuildPlatformChannels scans the analyzed binary for Flutter platform channel definitions.
func BuildPlatformChannels(cl *cluster.Result, pl *naming.PoolLookups, edges []disasm.CallEdgeRecord) []PlatformChannelRecord {
	if cl == nil || pl == nil {
		return nil
	}

	channelMap := make(map[string]*PlatformChannelRecord)
	getOrCreate := func(name, chType string) *PlatformChannelRecord {
		if rec, ok := channelMap[name]; ok {
			return rec
		}
		rec := &PlatformChannelRecord{
			ChannelName: name,
			ChannelType: chType,
		}
		channelMap[name] = rec
		return rec
	}

	// 1. Scan pool strings for candidate channel names.
	// Platform channel names typically follow reverse-domain or slash-delimited naming:
	// e.g. "plugins.flutter.io/battery", "com.app.auth/payment", "flutter/lifecycle"
	for _, pe := range cl.Pool {
		if pe.Kind == cluster.PoolTagged {
			str := pl.RefToStr[pe.RefID]
			if isCandidateChannelName(str) {
				chType := "method_channel"
				if strings.Contains(strings.ToLower(str), "event") {
					chType = "event_channel"
				}
				getOrCreate(str, chType)
			}
		}
	}

	chNames := make([]string, 0, len(channelMap))
	for name := range channelMap {
		chNames = append(chNames, name)
	}
	slices.Sort(chNames)

	// 2. Scan call edges for MethodChannel handlers and invocations.
	for _, edge := range edges {
		target := edge.Target
		if strings.Contains(target, "MethodChannel") || strings.Contains(target, "BasicMessageChannel") || strings.Contains(target, "EventChannel") {
			for _, chName := range chNames {
				rec := channelMap[chName]
				if strings.Contains(edge.FromFunc, chName) || strings.Contains(target, chName) {
					rec.CallSites = append(rec.CallSites, edge.FromFunc)
				}
			}
		}
	}

	var results []PlatformChannelRecord
	for _, chName := range chNames {
		rec := channelMap[chName]
		// Deduplicate call sites
		if len(rec.CallSites) > 1 {
			slices.Sort(rec.CallSites)
			rec.CallSites = slices.Compact(rec.CallSites)
		}
		results = append(results, *rec)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ChannelName < results[j].ChannelName
	})

	return results
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
