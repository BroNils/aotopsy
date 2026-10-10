package signal

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
)

// SourceSinkFinding represents lexical source/sink evidence connected by static
// function proximity. It deliberately does not claim value-level data flow:
// AOTopsy does not track the source value through SSA/memory into the sink.
type SourceSinkFinding struct {
	Source     string `json:"source"`
	Sink       string `json:"sink"`
	SourceFn   string `json:"source_func,omitempty"`
	SinkFn     string `json:"sink_func,omitempty"`
	Relation   string `json:"relation"` // same_function, direct_static_call, two_hop_static_call
	Confidence string `json:"confidence"`
}

// Source patterns: functions/APIs that read sensitive data.
// Patterns are matched with strings.Contains on the lowercased string value,
// so each one must be specific enough to not fire on ordinary vocabulary.
// The generic forms that were here first all had common false positives:
// "serial" is inside serialize/serialization/deserializer, "location" inside
// allocation/relocation, "token" inside tokenizer/tokenize, "session" inside
// sessionstorage-unrelated words. They are replaced by the qualified spellings.
var sourcePatterns = map[string]string{
	"imei":            "device_imei",
	"android_id":      "device_android_id",
	"serialnumber":    "device_serial",
	"getserial":       "device_serial",
	"deviceserial":    "device_serial",
	"mac_address":     "device_mac",
	"macaddress":      "device_mac",
	"advertising_id":  "device_adid",
	"advertisingid":   "device_adid",
	"phone_number":    "device_phone",
	"phonenumber":     "device_phone",
	"email":           "user_email",
	"password":        "user_password",
	"authtoken":       "auth_token",
	"accesstoken":     "auth_token",
	"idtoken":         "auth_token",
	"refreshtoken":    "auth_token",
	"sessionid":       "session_id",
	"sessiontoken":    "session_id",
	"getlocation":     "device_location",
	"currentlocation": "device_location",
	"locationmanager": "device_location",
	"geolocator":      "device_location",
	"latitude":        "device_location",
	"contacts":        "user_contacts",
	"addressbook":     "user_contacts",
	"camera":          "camera_access",
	"microphone":      "microphone_access",
	"biometric":       "biometric_data",
}

// Sink patterns: functions/APIs that send/store data.
//
// Patterns are matched via substring (strings.Contains on the lowercased
// string ref value), so they must be specific enough to avoid false positives.
// The bare substrings "log" and "print" matched unrelated words (dialog,
// catalog, algorithm, fingerprint, blueprint, sprint), so they use the
// call-site form "log(" / "print(" or the Dart-specific API names instead.
var sinkPatterns = map[string]string{
	// HTTP is a protocol family here; "https" already contains "http", so a
	// separate https entry would emit two source/sink findings for one endpoint.
	"http":              "network_http",
	"socket":            "network_socket",
	"MethodChannel":     "platform_channel",
	"writeFile":         "file_write",
	"writeAsString":     "file_write",
	"SharedPreferences": "shared_prefs",
	"sqflite":           "sqlite_db",
	// "hive" alone matched "archive"/"Archive"; the box API is the real signal.
	"hive.init":     "hive_box",
	"openbox":       "hive_box",
	"log(":          "logging",
	"print(":        "console_output",
	"debugprint":    "console_output",
	"developer.log": "logging",
	"analytics":     "analytics_send",
	"crashlytics":   "crash_report",
	"firebase":      "firebase_upload",
}

// WriteSourceSinkFindings identifies functions containing sensitive-source and sink
// lexical indicators, then records their static call-graph proximity. This is
// a triage aid, not value-level taint propagation.
func WriteSourceSinkFindings(outDir string, funcs []disasm.FuncRecord, stringRefs []disasm.StringRefRecord, edges []disasm.CallEdgeRecord) error {
	// Build function → patterns map
	funcSources := map[string]map[string]bool{}
	funcSinks := map[string]map[string]bool{}

	for _, sr := range stringRefs {
		if sr.Value == "" || sr.Func == "" {
			continue
		}
		val := strings.ToLower(sr.Value)
		for pat, label := range sourcePatterns {
			if strings.Contains(val, pat) {
				if funcSources[sr.Func] == nil {
					funcSources[sr.Func] = map[string]bool{}
				}
				funcSources[sr.Func][label] = true
			}
		}
		for pat, label := range sinkPatterns {
			if strings.Contains(strings.ToLower(sr.Value), strings.ToLower(pat)) {
				if funcSinks[sr.Func] == nil {
					funcSinks[sr.Func] = map[string]bool{}
				}
				funcSinks[sr.Func][label] = true
			}
		}
	}

	// Build call graph from in-memory edges (same source as
	// WriteBehavioralFindings) instead of re-reading call_edges.jsonl
	// from disk, so the two analyses share identical edge data.
	callerCallees := staticCallerCallees(funcs, edges)

	var findings []SourceSinkFinding
	seenFlows := map[string]bool{}
	const maxSourceSinkFindings = 10_000
	const maxSourceSinkTraversalLinks = 2_000_000
	addFinding := func(f SourceSinkFinding) error {
		// Witness identity is source/sink proximity, not the arbitrary
		// intermediate node used to discover it. The previous key included the
		// middle function, so a dense N-node graph emitted O(N^3) duplicate
		// witnesses for the same source→sink relationship.
		key := f.SourceFn + ":" + f.SinkFn + ":" + f.Source + ":" + f.Sink + ":" + f.Relation
		if seenFlows[key] {
			return nil
		}
		if len(findings) >= maxSourceSinkFindings {
			return fmt.Errorf("%w: more than %d findings", errSourceSinkBudget, maxSourceSinkFindings)
		}
		seenFlows[key] = true
		findings = append(findings, f)
		return nil
	}

	walk := func() error {
		// Pattern 1: source and sink indicators in the same function.
		for _, fn := range sortedKeys(funcSources) {
			sourceSet := funcSources[fn]
			sinks, ok := funcSinks[fn]
			if !ok {
				continue
			}
			for _, src := range sortedSet(sourceSet) {
				for _, sink := range sortedSet(sinks) {
					if err := addFinding(SourceSinkFinding{
						Source:     src,
						Sink:       sink,
						SourceFn:   fn,
						SinkFn:     fn,
						Relation:   "same_function",
						Confidence: "low",
					}); err != nil {
						return err
					}
				}
			}
		}

		// Pattern 2: source-indicator function directly calls sink-indicator function.
		for _, srcFn := range sortedKeys(funcSources) {
			sourceSet := funcSources[srcFn]
			callees := callerCallees[srcFn]
			if callees == nil {
				continue
			}
			for _, sinkFn := range sortedKeys(callees) {
				sinkSet, ok := funcSinks[sinkFn]
				if !ok {
					continue
				}
				for _, src := range sortedSet(sourceSet) {
					for _, sink := range sortedSet(sinkSet) {
						if err := addFinding(SourceSinkFinding{
							Source:     src,
							Sink:       sink,
							SourceFn:   srcFn,
							SinkFn:     sinkFn,
							Relation:   "direct_static_call",
							Confidence: "low",
						}); err != nil {
							return err
						}
					}
				}
			}
		}

		// Pattern 3: source and sink functions are separated by one static call hop.
		traversedLinks := 0
		for _, srcFn := range sortedKeys(funcSources) {
			sourceSet := funcSources[srcFn]
			callees1 := callerCallees[srcFn]
			if callees1 == nil {
				continue
			}
			for _, midFn := range sortedKeys(callees1) {
				callees2 := callerCallees[midFn]
				if callees2 == nil {
					continue
				}
				for _, sinkFn := range sortedKeys(callees2) {
					traversedLinks++
					if traversedLinks > maxSourceSinkTraversalLinks {
						return fmt.Errorf("%w: more than %d call-graph links", errSourceSinkBudget, maxSourceSinkTraversalLinks)
					}
					sinkSet, ok := funcSinks[sinkFn]
					if !ok {
						continue
					}
					for _, src := range sortedSet(sourceSet) {
						for _, sink := range sortedSet(sinkSet) {
							if err := addFinding(SourceSinkFinding{
								Source:     src,
								Sink:       sink,
								SourceFn:   srcFn,
								SinkFn:     sinkFn,
								Relation:   "two_hop_static_call",
								Confidence: "low",
							}); err != nil {
								return err
							}
						}
					}
				}
			}
		}
		return nil
	}
	var summary SourceSinkSummary
	if err := walk(); err != nil {
		if !errors.Is(err, errSourceSinkBudget) {
			return err
		}
		// The budget bounds a hostile graph, but this stage is advisory: keep
		// what was found (deterministic, thanks to the sorted walk) and say so
		// explicitly instead of failing the whole analysis.
		summary.Truncated = true
		summary.Reason = err.Error()
	}
	summary.Findings = len(findings)

	// Findings are discovered by iterating maps, so sort before writing:
	// otherwise the same binary produces a differently-ordered file on every
	// run, which breaks diffing two reports.
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.SourceFn != b.SourceFn {
			return a.SourceFn < b.SourceFn
		}
		if a.SinkFn != b.SinkFn {
			return a.SinkFn < b.SinkFn
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Sink != b.Sink {
			return a.Sink < b.Sink
		}
		return a.Relation < b.Relation
	})
	if err := writeSignalJSONL(filepath.Join(outDir, "source_sink_findings.jsonl"), findings); err != nil {
		return err
	}
	return jsonutil.WriteJSONFile(filepath.Join(outDir, SourceSinkSummaryFile), summary)
}

// SourceSinkSummaryFile states whether source_sink_findings.jsonl is complete. It is
// written on every run so a stale "truncated" verdict cannot outlive a rerun.
const SourceSinkSummaryFile = "source_sink_summary.json"

// SourceSinkSummary is the completeness verdict for source_sink_findings.jsonl.
type SourceSinkSummary struct {
	Findings  int    `json:"findings"`
	Truncated bool   `json:"truncated"`
	Reason    string `json:"reason,omitempty"`
}

var errSourceSinkBudget = errors.New("source/sink proximity budget exceeded")

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// YaraFinding represents a YARA-style rule match.
type YaraFinding struct {
	RuleName   string   `json:"rule_name"`
	Category   string   `json:"category"`
	Strings    []string `json:"matched_strings"`
	Functions  []string `json:"matched_functions,omitempty"`
	Confidence string   `json:"confidence"`
}

// YARA-style rules for security-relevant lexical indicators. A rule match is
// still lexical evidence; confidence below records how many distinct patterns
// were corroborated, and the category names avoid claiming malware identity.
var yaraRules = []struct {
	Name        string
	Category    string
	Strings     []string
	MinPatterns int
}{
	{"root_check_magisk", "anti_root", []string{"magisk", "MagiskManager", "/sbin/magisk", "magisk.db"}, 1},
	{"root_check_supersu", "anti_root", []string{"supersu", "Superuser", "/system/app/Superuser.apk", "eu.chainfire.supersu"}, 1},
	{"root_check_xposed", "anti_root", []string{"xposed", "XposedBridge", "de.robv.android.xposed", "XposedHelpers"}, 1},
	{"anti_frida_runtime", "anti_frida", []string{"frida-server", "frida-gadget", "frida-agent", "re.frida.server"}, 1},
	{"root_check_su", "anti_root", []string{"/system/bin/su", "/system/xbin/su", "which su", "superuser.apk"}, 1},
	{"anti_debug_ptrace", "anti_debug", []string{"ptrace", "TracerPid", "/proc/self/status", "isDebuggerAttached"}, 1},
	{"anti_debug_debugger", "anti_debug", []string{"android.os.Debug", "isDebuggerConnected"}, 1},
	{"ssl_pinning_cert", "ssl_pinning", []string{"certificatePinner", "CertificatePinning"}, 1},
	{"ssl_pinning_sha", "ssl_pinning", []string{"sha256/", "sha1/", "pinning", "publicKey"}, 2},
	{"accessibility_input_indicators", "accessibility_input", []string{"AccessibilityService", "onAccessibilityEvent", "keylogger", "KEY_EVENT"}, 2},
	{"screen_capture_indicators", "screen_capture", []string{"MediaProjection", "screenCapture", "createVirtualDisplay", "Screenshot"}, 2},
	{"sensitive_network_indicators", "source_network", []string{"imei", "android_id", "http://", "upload"}, 2},
	{"crypto_mining", "crypto_mining", []string{"monero", "xmrig", "cryptonight", "hashrate", "mining_pool"}, 2},
	{"banking_fraud_indicators", "fraud", []string{"otp", "sms_intercept", "banking", "credit_card", "cvv"}, 2},
	{"ad_fraud", "ad_fraud", []string{"click_injection", "ad_fraud", "impression_fraud", "click_bot"}, 2},
}

// WriteYaraFindings performs YARA-style string matching against security-relevant patterns.
func WriteYaraFindings(outDir string, stringRefs []disasm.StringRefRecord) error {
	// Build string → functions map
	stringFuncs := map[string][]string{}
	for _, sr := range stringRefs {
		if sr.Value == "" {
			continue
		}
		stringFuncs[sr.Value] = append(stringFuncs[sr.Value], sr.Func)
	}

	var findings []YaraFinding
	for _, rule := range yaraRules {
		var matchedStrings []string
		var matchedFuncs []string
		seenFuncs := map[string]bool{}
		matchedPatterns := map[int]bool{}
		patternsByFunc := map[string]map[int]bool{}
		// Pre-lowercase the rule patterns once per rule instead of calling
		// strings.ToLower(pattern) on every (pattern, val) pair.
		lowerPatterns := make([]string, len(rule.Strings))
		for i, pattern := range rule.Strings {
			lowerPatterns[i] = strings.ToLower(pattern)
		}
		for val, funcs := range stringFuncs {
			lowerVal := strings.ToLower(val) // pre-lowercase val once per string
			matched := false
			var matchedHere []int
			for pi, lp := range lowerPatterns {
				if strings.Contains(lowerVal, lp) {
					matchedPatterns[pi] = true
					matchedHere = append(matchedHere, pi)
					matched = true
				}
			}
			if matched {
				matchedStrings = append(matchedStrings, val)
				for _, fn := range funcs {
					if fn == "" {
						continue
					}
					if !seenFuncs[fn] {
						seenFuncs[fn] = true
						matchedFuncs = append(matchedFuncs, fn)
					}
					if patternsByFunc[fn] == nil {
						patternsByFunc[fn] = map[int]bool{}
					}
					for _, pi := range matchedHere {
						patternsByFunc[fn][pi] = true
					}
				}
			}
		}
		minPatterns := rule.MinPatterns
		if minPatterns < 1 {
			minPatterns = 1
		}
		if len(matchedStrings) > 0 && len(matchedPatterns) >= minPatterns {
			// stringFuncs is a map, so both slices come out in random order.
			sort.Strings(matchedStrings)
			sort.Strings(matchedFuncs)
			confidence := "low"
			for _, patternSet := range patternsByFunc {
				if len(patternSet) >= 2 {
					confidence = "medium"
					break
				}
			}
			findings = append(findings, YaraFinding{
				RuleName:   rule.Name,
				Category:   rule.Category,
				Strings:    matchedStrings,
				Functions:  matchedFuncs,
				Confidence: confidence,
			})
		}
	}

	return writeSignalJSONL(filepath.Join(outDir, "yara_findings.jsonl"), findings)
}

// BehavioralFinding represents a call-graph behavioral pattern.
type BehavioralFinding struct {
	Pattern    string   `json:"pattern"`
	Category   string   `json:"category"`
	Functions  []string `json:"functions"`
	EdgeCount  int      `json:"edge_count"`
	Confidence string   `json:"confidence"`
}

// staticCallerCallees projects only static function identities. Runtime
// observations stay separate, and a raw direct address becomes a function only
// when it exactly matches a functions.jsonl PC.
func staticCallerCallees(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord) map[string]map[string]bool {
	pcToName := make(map[string]string, len(funcs))
	for _, f := range funcs {
		if f.PC != "" && f.Name != "" {
			pcToName[strings.ToLower(strings.TrimSpace(f.PC))] = f.Name
		}
	}
	callerCallees := make(map[string]map[string]bool)
	for _, e := range edges {
		seen := make(map[string]bool)
		var targets []string
		for _, target := range e.ResolvedTargets() {
			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}
			if name := pcToName[strings.ToLower(target)]; name != "" {
				target = name
			} else if isRawSignalTarget(target) {
				continue
			}
			if !seen[target] {
				seen[target] = true
				targets = append(targets, target)
			}
		}
		if len(targets) == 0 && e.TargetAddress != "" {
			if name := pcToName[strings.ToLower(strings.TrimSpace(e.TargetAddress))]; name != "" {
				targets = append(targets, name)
			}
		}
		if len(targets) == 0 {
			continue
		}
		if callerCallees[e.FromFunc] == nil {
			callerCallees[e.FromFunc] = make(map[string]bool)
		}
		for _, target := range targets {
			callerCallees[e.FromFunc][target] = true
		}
	}
	return callerCallees
}

// WriteBehavioralFindings finds security-relevant adjacency patterns in the
// static call graph. Function categories are name heuristics, so these records
// describe graph relationships and never claim value flow or malicious intent.
func WriteBehavioralFindings(outDir string, funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord) error {
	// Build function name → category map based on name patterns.
	// Patterns are chosen to avoid false positives from framework names
	// (e.g., _RootZone should NOT match "root_check").
	funcCategory := map[string]string{}
	for _, f := range funcs {
		name := strings.ToLower(f.Name)
		owner := strings.ToLower(f.Owner)
		full := name + " " + owner
		switch {
		// root_check: specific root/jailbreak detection patterns
		case strings.Contains(full, "checkroot") || strings.Contains(full, "isrooted") ||
			strings.Contains(full, "jailbreak") || strings.Contains(full, "rootdetect") ||
			strings.Contains(full, "rootcheck") || strings.Contains(full, "supersu") ||
			strings.Contains(full, "magisk"):
			funcCategory[f.Name] = "root_check"
		// anti_debug: debugger detection
		case strings.Contains(full, "isdebugger") || strings.Contains(full, "debuggerconnected") ||
			strings.Contains(full, "ptrace") || strings.Contains(full, "antidebug") ||
			strings.Contains(full, "debug_detect") || strings.Contains(full, "checkdebug"):
			funcCategory[f.Name] = "anti_debug"
		// anti_analysis: frida/xposed detection
		case strings.Contains(full, "frida") || strings.Contains(full, "xposed") ||
			strings.Contains(full, "substrate") || strings.Contains(full, "riru") ||
			strings.Contains(full, "zygisk"):
			funcCategory[f.Name] = "anti_analysis"
		// crypto: encryption/decryption
		case strings.Contains(full, "encrypt") || strings.Contains(full, "decrypt") ||
			strings.Contains(full, "cipher") || strings.Contains(full, "aes_") ||
			strings.Contains(full, "rsa_") || strings.Contains(full, "sha256") ||
			strings.Contains(full, "hmac"):
			funcCategory[f.Name] = "crypto"
		// ssl: SSL/TLS pinning
		case strings.Contains(full, "sslpin") || strings.Contains(full, "certificatepin") ||
			strings.Contains(full, "tlspinning") || strings.Contains(full, "pinning"):
			funcCategory[f.Name] = "ssl"
		// network: HTTP/network communication
		case strings.Contains(full, "httpclient") || strings.Contains(full, "httprequest") ||
			strings.Contains(full, "networkrequest") || strings.Contains(full, "sendrequest") ||
			strings.Contains(full, "apicall") || strings.Contains(full, "uploaddata"):
			funcCategory[f.Name] = "network"
		// file_io: file system access
		case strings.Contains(full, "writefile") || strings.Contains(full, "readfile") ||
			strings.Contains(full, "savefile") || strings.Contains(full, "openfile") ||
			strings.Contains(full, "deletefile"):
			funcCategory[f.Name] = "file_io"
		// location: GPS/location access
		case strings.Contains(full, "getlocation") || strings.Contains(full, "currentlocation") ||
			strings.Contains(full, "gpslocation") || strings.Contains(full, "geolocator") ||
			strings.Contains(full, "locationupdate"):
			funcCategory[f.Name] = "location"
		// camera: camera access
		case strings.Contains(full, "takepicture") || strings.Contains(full, "opencamera") ||
			strings.Contains(full, "camerastart") || strings.Contains(full, "capturephoto"):
			funcCategory[f.Name] = "camera"
		// personal_data: contacts/SMS
		case strings.Contains(full, "readcontact") || strings.Contains(full, "getsms") ||
			strings.Contains(full, "readsms") || strings.Contains(full, "contactlist"):
			funcCategory[f.Name] = "personal_data"
		// credential: tokens/passwords
		case strings.Contains(full, "gettoken") || strings.Contains(full, "authtoken") ||
			strings.Contains(full, "password") || strings.Contains(full, "credential") ||
			strings.Contains(full, "apikey") || strings.Contains(full, "secretkey"):
			funcCategory[f.Name] = "credential"
		}
	}

	// Build the static call graph from semantic identities. Exact direct
	// addresses are resolved only when they match a functions.jsonl PC.
	callerCallees := staticCallerCallees(funcs, edges)

	// Identify behavioral patterns
	var findings []BehavioralFinding

	// Pattern 1: root_check → anti_debug (root check followed by anti-debug)
	rootCheckFuncs := []string{}
	antiDebugFuncs := []string{}
	for fn, cat := range funcCategory {
		if cat == "root_check" {
			rootCheckFuncs = append(rootCheckFuncs, fn)
		}
		if cat == "anti_debug" {
			antiDebugFuncs = append(antiDebugFuncs, fn)
		}
	}
	if len(rootCheckFuncs) > 0 && len(antiDebugFuncs) > 0 {
		// Check if any root_check function calls anti_debug function
		for _, rootFn := range rootCheckFuncs {
			callees := callerCallees[rootFn]
			for antiFn := range callees {
				if funcCategory[antiFn] == "anti_debug" {
					findings = append(findings, BehavioralFinding{
						Pattern:    "root_check_calls_anti_debug",
						Category:   "anti_analysis",
						Functions:  []string{rootFn, antiFn},
						EdgeCount:  1,
						Confidence: "low",
					})
				}
			}
		}
	}

	// Pattern 2: credential-named function statically calls network-named function.
	credFuncs := []string{}
	netFuncs := []string{}
	for fn, cat := range funcCategory {
		if cat == "credential" {
			credFuncs = append(credFuncs, fn)
		}
		if cat == "network" {
			netFuncs = append(netFuncs, fn)
		}
	}
	if len(credFuncs) > 0 && len(netFuncs) > 0 {
		for _, credFn := range credFuncs {
			callees := callerCallees[credFn]
			for netFn := range callees {
				if funcCategory[netFn] == "network" {
					findings = append(findings, BehavioralFinding{
						Pattern:    "credential_function_calls_network_function",
						Category:   "credential_network_adjacency",
						Functions:  []string{credFn, netFn},
						EdgeCount:  1,
						Confidence: "low",
					})
				}
			}
		}
	}

	// Pattern 3: location-named function statically calls network-named function.
	locFuncs := []string{}
	for fn, cat := range funcCategory {
		if cat == "location" {
			locFuncs = append(locFuncs, fn)
		}
	}
	if len(locFuncs) > 0 && len(netFuncs) > 0 {
		for _, locFn := range locFuncs {
			callees := callerCallees[locFn]
			for netFn := range callees {
				if funcCategory[netFn] == "network" {
					findings = append(findings, BehavioralFinding{
						Pattern:    "location_function_calls_network_function",
						Category:   "location_network_adjacency",
						Functions:  []string{locFn, netFn},
						EdgeCount:  1,
						Confidence: "low",
					})
				}
			}
		}
	}

	// Pattern 4: crypto-named function statically calls network-named function.
	cryptoFuncs := []string{}
	for fn, cat := range funcCategory {
		if cat == "crypto" {
			cryptoFuncs = append(cryptoFuncs, fn)
		}
	}
	if len(cryptoFuncs) > 0 && len(netFuncs) > 0 {
		for _, cryptoFn := range cryptoFuncs {
			callees := callerCallees[cryptoFn]
			for netFn := range callees {
				if funcCategory[netFn] == "network" {
					findings = append(findings, BehavioralFinding{
						Pattern:    "crypto_function_calls_network_function",
						Category:   "crypto_network_adjacency",
						Functions:  []string{cryptoFn, netFn},
						EdgeCount:  1,
						Confidence: "low",
					})
				}
			}
		}
	}

	// Pattern 5: Count functions by category for summary
	categoryCounts := map[string]int{}
	for _, cat := range funcCategory {
		categoryCounts[cat]++
	}
	for cat, count := range categoryCounts {
		if count > 0 {
			findings = append(findings, BehavioralFinding{
				Pattern:    fmt.Sprintf("category_%s_count", cat),
				Category:   cat,
				Functions:  nil,
				EdgeCount:  count,
				Confidence: "info",
			})
		}
	}

	// funcCategory and callerCallees are maps: sort so the output file is
	// reproducible across runs.
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Pattern != b.Pattern {
			return a.Pattern < b.Pattern
		}
		return strings.Join(a.Functions, ",") < strings.Join(b.Functions, ",")
	})
	return writeSignalJSONL(filepath.Join(outDir, "behavioral_findings.jsonl"), findings)
}
