package analysis

import (
	"encoding/json"
	"strings"
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/naming"
)

func TestBuildFfiBridges(t *testing.T) {
	cl := &cluster.Result{
		FfiTrampolines: []cluster.FfiTrampolineInfo{
			{
				RefID:             101,
				SignatureTypeRef:  201,
				CSignatureRef:     202,
				CallbackTargetRef: 203,
				CallbackID:        0,
				FfiKindRaw:        4,
			},
			{
				RefID:             102,
				CallbackTargetRef: cluster.RefNull,
				CallbackID:        -1,
				FfiKindRaw:        0,
			},
		},
	}

	pl := &naming.PoolLookups{
		RefToStr: map[int]string{
			cluster.RefNull: "null",
			201:             "int Function(Pointer, int)",
			202:             "Int32 Function(Pointer<Uint8>, Uint32)",
			203:             "package:my_app/crypto.dart::nativeCallback",
		},
	}

	records := BuildFfiBridges("3.2.5", cl, pl)
	if len(records) != 2 {
		t.Fatalf("expected 2 FfiBridgeRecords, got %d", len(records))
	}

	if records[0].FfiKindRaw != 4 {
		t.Errorf("expected raw FFI kind 4, got %d", records[0].FfiKindRaw)
	}
	if records[0].Direction != cluster.FfiDirectionCallback {
		t.Errorf("expected callback direction, got %q", records[0].Direction)
	}
	if records[0].CallbackID != 0 {
		t.Errorf("expected callback_id 0, got %d", records[0].CallbackID)
	}
	if records[0].DartSignature != "int Function(Pointer, int)" {
		t.Errorf("unexpected dart signature: %q", records[0].DartSignature)
	}
	if records[0].CallbackTarget != "package:my_app/crypto.dart::nativeCallback" {
		t.Errorf("unexpected callback target: %q", records[0].CallbackTarget)
	}

	if records[1].FfiKindRaw != 0 {
		t.Errorf("expected raw FFI kind 0, got %d", records[1].FfiKindRaw)
	}
	if records[1].Direction != cluster.FfiDirectionOutbound {
		t.Errorf("expected outbound direction, got %q", records[1].Direction)
	}
	if records[1].CallbackTarget != "" {
		t.Errorf("outbound bridge exposed a callback target: %q", records[1].CallbackTarget)
	}

	wire, err := json.Marshal(records[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"callback_id":0`) {
		t.Fatalf("callback_id=0 was dropped from bridge evidence: %s", wire)
	}
}

func TestBuildPlatformChannels(t *testing.T) {
	cl := &cluster.Result{
		Pool: []cluster.PoolEntry{
			{
				Index: 0,
				Kind:  cluster.PoolTagged,
				RefID: 10,
			},
			{
				Index: 1,
				Kind:  cluster.PoolTagged,
				RefID: 11,
			},
		},
	}

	pl := &naming.PoolLookups{
		RefToStr: map[int]string{
			10: "plugins.flutter.io/url_launcher",
			11: "com.example.app/payments",
		},
	}

	edges := []disasm.CallEdgeRecord{
		{
			FromFunc: "package:my_app/main.dart::launchURL",
			Target:   "package:flutter/services.dart::MethodChannel.invokeMethod",
		},
		{
			FromFunc: "package:my_app/pay.dart::sendPayment",
			Target:   "package:flutter/services.dart::BasicMessageChannel.send",
		},
	}
	stringRefs := []disasm.StringRefRecord{
		{Func: "package:my_app/main.dart::launchURL", Value: "plugins.flutter.io/url_launcher"},
		{Func: "package:my_app/pay.dart::sendPayment", Value: "com.example.app/payments"},
	}

	channels := BuildPlatformChannels(cl, pl, nil, nil, edges, stringRefs)
	if len(channels) != 2 {
		t.Fatalf("expected 2 platform channels, got %d", len(channels))
	}

	foundURL := false
	for _, ch := range channels {
		if ch.ChannelName == "plugins.flutter.io/url_launcher" {
			foundURL = true
			if len(ch.ChannelTypes) != 1 || ch.ChannelTypes[0] != "method_channel" {
				t.Errorf("expected method_channel, got %q", ch.ChannelTypes)
			}
			if len(ch.CallSites) != 1 || ch.CallSites[0] != "package:my_app/main.dart::launchURL" {
				t.Errorf("unexpected callsites: %q", ch.CallSites)
			}
		}
	}
	if !foundURL {
		t.Errorf("expected to find plugins.flutter.io/url_launcher channel")
	}
}

func TestBuildPlatformChannelsDoesNotTreatViaAsAPIIdentity(t *testing.T) {
	cl := &cluster.Result{Pool: []cluster.PoolEntry{{Index: 0, Kind: cluster.PoolTagged, RefID: 10}}}
	pl := &naming.PoolLookups{RefToStr: map[int]string{10: "plugins.flutter.io/example"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "caller",
		Via:      "package:flutter/services.dart::MethodChannel.invokeMethod",
	}}
	refs := []disasm.StringRefRecord{{Func: "caller", Value: "plugins.flutter.io/example"}}

	channels := BuildPlatformChannels(cl, pl, nil, nil, edges, refs)
	if len(channels) != 0 {
		t.Fatalf("Via provenance fabricated platform API call: %+v", channels)
	}
}

func TestBuildPlatformChannelsResolvesDirectTargetAddressThroughFunctions(t *testing.T) {
	cl := &cluster.Result{Pool: []cluster.PoolEntry{{Index: 0, Kind: cluster.PoolTagged, RefID: 10}}}
	pl := &naming.PoolLookups{RefToStr: map[int]string{10: "plugins.flutter.io/example"}}
	funcs := []disasm.FuncRecord{{Name: "package:flutter/services.dart::MethodChannel.invokeMethod", PC: "0x2000"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "caller", FromPC: "0x1000", Kind: "bl", TargetAddress: "0x2000",
	}}
	refs := []disasm.StringRefRecord{{Func: "caller", Value: "plugins.flutter.io/example"}}

	channels := BuildPlatformChannels(cl, pl, nil, funcs, edges, refs)
	if len(channels) != 1 || len(channels[0].ChannelTypes) != 1 || channels[0].ChannelTypes[0] != "method_channel" {
		t.Fatalf("direct-address channel binding = %+v", channels)
	}
}

// Framework channels such as `flutter/platform` are `const MethodChannel(...)`
// instances living in the snapshot heap: no code constructs them, so the
// string+call join finds nothing. The Instance itself is the evidence.
func TestBuildPlatformChannelsFromConstInstances(t *testing.T) {
	cl := &cluster.Result{Instances: []cluster.InstanceInfo{
		// MethodChannel(name, codec, binaryMessenger): name is the first slot.
		{RefID: 1, CID: 351, Fields: []cluster.InstanceFieldRef{{ByteOffset: 12, Ref: 40}, {ByteOffset: 8, Ref: 10}}},
		// BasicMessageChannel<T>: TypeArguments first, then name.
		{RefID: 2, CID: 353, Fields: []cluster.InstanceFieldRef{{ByteOffset: 8, Ref: 41}, {ByteOffset: 12, Ref: 11}}},
		// EventChannel with a non-reverse-domain name.
		{RefID: 3, CID: 354, Fields: []cluster.InstanceFieldRef{{ByteOffset: 8, Ref: 12}}},
		// Unrelated class with a string in slot 0.
		{RefID: 4, CID: 999, Fields: []cluster.InstanceFieldRef{{ByteOffset: 8, Ref: 12}}},
	}}
	pl := &naming.PoolLookups{RefToStr: map[int]string{10: "flutter/platform", 11: "flutter/keydata", 12: "battery_events", 40: "codec-not-a-name"}}
	layouts := []DartClassLayout{
		{ClassName: "MethodChannel", ClassID: 351},
		{ClassName: "BasicMessageChannel", ClassID: 353},
		{ClassName: "EventChannel", ClassID: 354},
		{ClassName: "Widget", ClassID: 999},
	}
	got := map[string]PlatformChannelRecord{}
	for _, ch := range BuildPlatformChannels(cl, pl, layouts, nil, nil, nil) {
		got[ch.ChannelName] = ch
	}
	want := map[string]string{"flutter/platform": "method_channel", "flutter/keydata": "basic_message_channel", "battery_events": "event_channel"}
	if len(got) != len(want) {
		t.Fatalf("channels = %+v, want %v", got, want)
	}
	for name, typ := range want {
		ch, ok := got[name]
		if !ok || len(ch.ChannelTypes) != 1 || ch.ChannelTypes[0] != typ || ch.Confidence != "high" || ch.ConstInstances != 1 {
			t.Errorf("%s = %+v, want one %s const instance with high confidence", name, ch, typ)
		}
	}
}

func TestBuildNativeCapabilitiesDoesNotClaimUsageFromSnapshotName(t *testing.T) {
	vm := &cluster.Result{Strings: []cluster.ParsedString{
		{RefID: 10, Value: "Socket_CreateConnect"},
		{RefID: 11, Value: "not_a_native"},
	}}
	got := BuildNativeCapabilities("3.12.2", nil, vm)
	if len(got) != 1 {
		t.Fatalf("native inventory = %+v, want one exact SDK-native name", got)
	}
	rec := got[0]
	if rec.Name != "Socket_CreateConnect" || rec.Evidence != "snapshot_native_name" || rec.IdentityConfidence != "high" {
		t.Fatalf("native identity evidence = %+v", rec)
	}
	if rec.UsageEvidence != "not_established" {
		t.Fatalf("snapshot-name inventory claimed native usage: %+v", rec)
	}
}

func TestBuildDeobfuscationMap(t *testing.T) {
	cl := &cluster.Result{
		Classes: []cluster.ClassInfo{
			{
				RefID:          1,
				NameRefID:      10,
				ClassID:        100,
				SuperTypeRefID: 20,
			},
			{
				RefID:       2,
				NameRefID:   12,
				ClassID:     200,
				TypeArgsOff: cluster.NoTypeArguments,
			},
		},
		Types: []cluster.TypeInfo{{RefID: 20, ClassID: 200}},
	}

	pl := &naming.PoolLookups{
		RefToStr: map[int]string{
			10: "a",
			12: "ChangeNotifier",
		},
		RefToNamed: map[int]*cluster.NamedObject{
			1: {RefID: 1, NameRefID: 10},
			2: {RefID: 2, NameRefID: 12},
		},
	}

	stringRefs := []disasm.StringRefRecord{
		{
			Func:  "a.login",
			Value: "https://api.example.com/v1/auth/login",
		},
	}

	records := BuildDeobfuscationMap(cl, pl, stringRefs)
	if len(records) != 1 {
		t.Fatalf("expected 1 deobfuscated record, got %d", len(records))
	}

	rec := records[0]
	if rec.ObfuscatedName != "a" {
		t.Errorf("expected name 'a', got %q", rec.ObfuscatedName)
	}
	if rec.ClassID != 100 {
		t.Errorf("expected class ID 100, got %d", rec.ClassID)
	}
	if rec.SuperClassName != "ChangeNotifier" {
		t.Errorf("expected superclass 'ChangeNotifier', got %q", rec.SuperClassName)
	}
	if rec.PredictedRole != "API Client / Network Repository" {
		t.Errorf("expected predicted role 'API Client / Network Repository', got %q", rec.PredictedRole)
	}
	if rec.Confidence < 0.9 {
		t.Errorf("expected confidence >= 0.9, got %f", rec.Confidence)
	}
}

func TestBuildDeobfuscationMapDoesNotInventRoleWithoutEvidence(t *testing.T) {
	cl := &cluster.Result{Classes: []cluster.ClassInfo{{RefID: 1, NameRefID: 10, ClassID: 100}}}
	pl := &naming.PoolLookups{RefToStr: map[int]string{10: "a"}}

	records := BuildDeobfuscationMap(cl, pl, nil)
	if len(records) != 1 {
		t.Fatalf("expected 1 deobfuscated record, got %d", len(records))
	}
	if got := records[0].PredictedRole; got != "Unknown" {
		t.Fatalf("predicted role without evidence = %q, want Unknown", got)
	}
	if got := records[0].Confidence; got != 0 {
		t.Fatalf("confidence without evidence = %f, want 0", got)
	}
	if len(records[0].Clues) != 0 {
		t.Fatalf("unexpected clues without evidence: %v", records[0].Clues)
	}
}

func TestBuildDeobfuscationMapRejectsAmbiguousOwnerStringEvidence(t *testing.T) {
	cl := &cluster.Result{Classes: []cluster.ClassInfo{
		{RefID: 1, NameRefID: 10, ClassID: 100},
		{RefID: 2, NameRefID: 11, ClassID: 200},
	}}
	pl := &naming.PoolLookups{RefToStr: map[int]string{10: "a", 11: "a"}}
	stringRefs := []disasm.StringRefRecord{{
		Func:  "a.login",
		Value: "https://api.example.com/v1/auth/login",
	}}

	records := BuildDeobfuscationMap(cl, pl, stringRefs)
	if len(records) != 2 {
		t.Fatalf("expected 2 deobfuscated records, got %d", len(records))
	}
	for _, rec := range records {
		if rec.PredictedRole != "Unknown" || rec.Confidence != 0 {
			t.Fatalf("ambiguous owner %q class %d received foreign evidence: %+v", rec.ObfuscatedName, rec.ClassID, rec)
		}
		if len(rec.Clues) != 0 {
			t.Fatalf("ambiguous owner class %d received clues: %v", rec.ClassID, rec.Clues)
		}
	}
}
