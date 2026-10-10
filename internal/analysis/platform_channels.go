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
	// ConstInstances counts canonical const channel Instances in the snapshot
	// carrying this name (exact evidence; see BuildPlatformChannels).
	ConstInstances int    `json:"const_instances,omitempty"`
	Confidence     string `json:"confidence"`
}

// channelClassTypes maps the Flutter services channel classes to the channel
// type reported in platform_channels.jsonl. OptionalMethodChannel extends
// MethodChannel.
var channelClassTypes = map[string]string{
	"MethodChannel":         "method_channel",
	"OptionalMethodChannel": "method_channel",
	"EventChannel":          "event_channel",
	"BasicMessageChannel":   "basic_message_channel",
}

// channelNameSlotWindow is how many leading reference slots of a channel instance
// are searched for the `name` String. Flutter declares `final String name`
// first in MethodChannel and EventChannel; BasicMessageChannel<T> puts its
// TypeArguments pointer ahead of it.
const channelNameSlotWindow = 3

// BuildPlatformChannels reports Flutter platform channels from two independent,
// exact kinds of evidence instead of guessing from string spelling:
//
//  1. const channel instances: the framework's own channels
//     (`flutter/platform`, `flutter/navigation`, ...) and any app channel written
//     as `const MethodChannel('x')` are canonical heap Instances in the snapshot,
//     never constructed by code. An Instance of MethodChannel / EventChannel /
//     BasicMessageChannel (class names from layouts) whose leading slots hold a
//     String is exactly such a channel. Confidence "high".
//  2. dynamic constructions: a function references a channel-looking string AND
//     calls a Flutter channel API. A reverse-domain string by itself is not proof.
//     Confidence "medium".
func BuildPlatformChannels(cl *cluster.Result, pl *naming.PoolLookups, layouts []DartClassLayout, funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord, stringRefs []disasm.StringRefRecord) []PlatformChannelRecord {
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

	// 0. Const channel instances (exact).
	channelByCID := make(map[int]string)
	for _, l := range layouts {
		if typ, ok := channelClassTypes[l.ClassName]; ok {
			channelByCID[int(l.ClassID)] = typ
		}
	}
	constInstances := make(map[string]int)
	if len(channelByCID) > 0 {
		for i := range cl.Instances {
			inst := &cl.Instances[i]
			typ, ok := channelByCID[inst.CID]
			if !ok {
				continue
			}
			slots := append([]cluster.InstanceFieldRef(nil), inst.Fields...)
			sort.Slice(slots, func(a, b int) bool { return slots[a].ByteOffset < slots[b].ByteOffset })
			if len(slots) > channelNameSlotWindow {
				slots = slots[:channelNameSlotWindow]
			}
			for _, slot := range slots {
				name, ok := pl.StringForRef(slot.Ref)
				if !ok || name == "" {
					continue
				}
				rec := getOrCreate(name)
				rec.ChannelTypes = append(rec.ChannelTypes, typ)
				constInstances[name]++
				break
			}
		}
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
		if n := constInstances[rec.ChannelName]; n > 0 {
			rec.ConstInstances = n
			rec.Confidence = "high"
		}
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
