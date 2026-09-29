package analysis

import (
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
				CallbackID:        7,
				CallbackKindRaw:   4,
			},
			{
				RefID:           102,
				CallbackKindRaw: 0,
			},
		},
	}

	pl := &naming.PoolLookups{
		RefToStr: map[int]string{
			201: "int Function(Pointer, int)",
			202: "Int32 Function(Pointer<Uint8>, Uint32)",
			203: "package:my_app/crypto.dart::nativeCallback",
		},
	}

	records := BuildFfiBridges(cl, pl)
	if len(records) != 2 {
		t.Fatalf("expected 2 FfiBridgeRecords, got %d", len(records))
	}

	if records[0].CallbackKindRaw != 4 {
		t.Errorf("expected raw callback kind 4, got %d", records[0].CallbackKindRaw)
	}
	if records[0].CallbackID != 7 {
		t.Errorf("expected callback_id 7, got %d", records[0].CallbackID)
	}
	if records[0].DartSignature != "int Function(Pointer, int)" {
		t.Errorf("unexpected dart signature: %q", records[0].DartSignature)
	}
	if records[0].CallbackTarget != "package:my_app/crypto.dart::nativeCallback" {
		t.Errorf("unexpected callback target: %q", records[0].CallbackTarget)
	}

	if records[1].CallbackKindRaw != 0 {
		t.Errorf("expected raw callback kind 0, got %d", records[1].CallbackKindRaw)
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

	channels := BuildPlatformChannels(cl, pl, edges, stringRefs)
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
