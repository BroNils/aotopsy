package signal

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"aotopsy/internal/disasm"
)

// TaintFinding represents a potential source→sink data flow.
type TaintFinding struct {
	Source     string `json:"source"`
	Sink       string `json:"sink"`
	SourceFn   string `json:"source_func,omitempty"`
	SinkFn     string `json:"sink_func,omitempty"`
	FlowType   string `json:"flow_type"` // "imei_to_network", "token_to_storage", etc.
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
	"http":              "network_http",
	"https":             "network_https",
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

// WriteTaintFindings performs taint analysis by identifying functions that
// access source patterns and functions that access sink patterns, then
// checking the call graph for source→sink flows (including cross-function).
func WriteTaintFindings(outDir string, stringRefs []disasm.StringRefRecord, edges []disasm.CallEdgeRecord) error {
	// Build function → patterns map
	funcSources := map[string][]string{}
	funcSinks := map[string][]string{}

	for _, sr := range stringRefs {
		if sr.Value == "" || sr.Func == "" {
			continue
		}
		val := strings.ToLower(sr.Value)
		for pat, label := range sourcePatterns {
			if strings.Contains(val, pat) {
				funcSources[sr.Func] = append(funcSources[sr.Func], label)
			}
		}
		for pat, label := range sinkPatterns {
			if strings.Contains(strings.ToLower(sr.Value), strings.ToLower(pat)) {
				funcSinks[sr.Func] = append(funcSinks[sr.Func], label)
			}
		}
	}

	// Build call graph from in-memory edges (same source as
	// WriteBehavioralFindings) instead of re-reading call_edges.jsonl
	// from disk, so the two analyses share identical edge data.
	callerCallees := map[string]map[string]bool{}
	for _, e := range edges {
		if e.Target == "" {
			continue
		}
		if callerCallees[e.FromFunc] == nil {
			callerCallees[e.FromFunc] = map[string]bool{}
		}
		callerCallees[e.FromFunc][e.Target] = true
	}

	var findings []TaintFinding
	seenFlows := map[string]bool{}

	// Pattern 1: same-function taint (source and sink in same function)
	for fn, sources := range funcSources {
		sinks, ok := funcSinks[fn]
		if !ok {
			continue
		}
		for _, src := range sources {
			for _, sink := range sinks {
				key := fn + ":" + src + ":" + sink
				if !seenFlows[key] {
					seenFlows[key] = true
					findings = append(findings, TaintFinding{
						Source:     src,
						Sink:       sink,
						SourceFn:   fn,
						SinkFn:     fn,
						FlowType:   fmt.Sprintf("%s_to_%s", src, sink),
						Confidence: "low",
					})
				}
			}
		}
	}

	// Pattern 2: cross-function taint (source function calls sink function)
	for srcFn, sources := range funcSources {
		callees := callerCallees[srcFn]
		if callees == nil {
			continue
		}
		for sinkFn := range callees {
			sinks, ok := funcSinks[sinkFn]
			if !ok {
				continue
			}
			for _, src := range sources {
				for _, sink := range sinks {
					key := srcFn + ":" + sinkFn + ":" + src + ":" + sink
					if !seenFlows[key] {
						seenFlows[key] = true
						findings = append(findings, TaintFinding{
							Source:     src,
							Sink:       sink,
							SourceFn:   srcFn,
							SinkFn:     sinkFn,
							FlowType:   fmt.Sprintf("%s_to_%s", src, sink),
							Confidence: "medium",
						})
					}
				}
			}
		}
	}

	// Pattern 3: 2-hop taint (source → intermediate → sink)
	for srcFn, sources := range funcSources {
		callees1 := callerCallees[srcFn]
		if callees1 == nil {
			continue
		}
		for midFn := range callees1 {
			callees2 := callerCallees[midFn]
			if callees2 == nil {
				continue
			}
			for sinkFn := range callees2 {
				sinks, ok := funcSinks[sinkFn]
				if !ok {
					continue
				}
				for _, src := range sources {
					for _, sink := range sinks {
						key := srcFn + ":" + midFn + ":" + sinkFn + ":" + src + ":" + sink
						if !seenFlows[key] {
							seenFlows[key] = true
							findings = append(findings, TaintFinding{
								Source:     src,
								Sink:       sink,
								SourceFn:   srcFn,
								SinkFn:     sinkFn,
								FlowType:   fmt.Sprintf("%s_to_%s_via_%s", src, sink, midFn),
								Confidence: "low",
							})
						}
					}
				}
			}
		}
	}

	if len(findings) == 0 {
		return nil
	}
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
		return a.FlowType < b.FlowType
	})
	return writeJSONLFile(filepath.Join(outDir, "taint_findings.jsonl"), findings)
}

// YaraFinding represents a YARA-style rule match.
type YaraFinding struct {
	RuleName  string   `json:"rule_name"`
	Category  string   `json:"category"`
	Strings   []string `json:"matched_strings"`
	Functions []string `json:"matched_functions,omitempty"`
}

// YARA-style rules for common malware behaviors.
var yaraRules = []struct {
	Name     string
	Category string
	Strings  []string
}{
	{"root_check_magisk", "anti_root", []string{"magisk", "MagiskManager", "/sbin/magisk", "magisk.db"}},
	{"root_check_supersu", "anti_root", []string{"supersu", "Superuser", "/system/app/Superuser.apk", "eu.chainfire.supersu"}},
	{"root_check_xposed", "anti_root", []string{"xposed", "XposedBridge", "de.robv.android.xposed", "XposedHelpers"}},
	{"root_check_frida", "anti_frida", []string{"frida-server", "frida-gadget", "frida-agent", "re.frida.server"}},
	{"root_check_su", "anti_root", []string{"/system/bin/su", "/system/xbin/su", "which su", "superuser.apk"}},
	{"anti_debug_ptrace", "anti_debug", []string{"ptrace", "TracerPid", "/proc/self/status", "isDebuggerAttached"}},
	{"anti_debug_debugger", "anti_debug", []string{"debugger", "android.os.Debug", "isDebuggerConnected"}},
	{"ssl_pinning_cert", "ssl_pinning", []string{"certificatePinner", "CertificatePinning", "X509TrustManager", "OkHttp"}},
	{"ssl_pinning_sha", "ssl_pinning", []string{"sha256/", "sha1/", "pinning", "publicKey"}},
	{"keylogger_accessibility", "spyware", []string{"AccessibilityService", "onAccessibilityEvent", "keylogger", "KEY_EVENT"}},
	{"screen_capture", "spyware", []string{"MediaProjection", "screenCapture", "createVirtualDisplay", "Screenshot"}},
	{"data_exfil_http", "data_theft", []string{"imei", "android_id", "http://", "upload"}},
	{"crypto_mining", "crypto_mining", []string{"monero", "xmrig", "cryptonight", "hashrate", "mining_pool"}},
	{"banking_trojan", "fraud", []string{"otp", "sms_intercept", "banking", "credit_card", "cvv"}},
	{"ad_fraud", "ad_fraud", []string{"click_injection", "ad_fraud", "impression_fraud", "click_bot"}},
}

// WriteYaraFindings performs YARA-style string matching against known malware patterns.
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
		// Pre-lowercase the rule patterns once per rule instead of calling
		// strings.ToLower(pattern) on every (pattern, val) pair.
		lowerPatterns := make([]string, len(rule.Strings))
		for i, pattern := range rule.Strings {
			lowerPatterns[i] = strings.ToLower(pattern)
		}
		for val, funcs := range stringFuncs {
			lowerVal := strings.ToLower(val) // pre-lowercase val once per string
			matched := false
			for _, lp := range lowerPatterns {
				if strings.Contains(lowerVal, lp) {
					matched = true
					break
				}
			}
			if matched {
				matchedStrings = append(matchedStrings, val)
				for _, fn := range funcs {
					if !seenFuncs[fn] {
						seenFuncs[fn] = true
						matchedFuncs = append(matchedFuncs, fn)
					}
				}
			}
		}
		if len(matchedStrings) > 0 {
			// stringFuncs is a map, so both slices come out in random order.
			sort.Strings(matchedStrings)
			sort.Strings(matchedFuncs)
			findings = append(findings, YaraFinding{
				RuleName:  rule.Name,
				Category:  rule.Category,
				Strings:   matchedStrings,
				Functions: matchedFuncs,
			})
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return writeJSONLFile(filepath.Join(outDir, "yara_findings.jsonl"), findings)
}

// BehavioralFinding represents a call-graph behavioral pattern.
type BehavioralFinding struct {
	Pattern    string   `json:"pattern"`
	Category   string   `json:"category"`
	Functions  []string `json:"functions"`
	EdgeCount  int      `json:"edge_count"`
	Confidence string   `json:"confidence"`
}

// WriteBehavioralFindings performs call-graph behavioral analysis.
// Identifies common malware behavioral patterns from the call graph.
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

	// Build a PC → function name map so hex VA call targets (e.Target == "0x...")
	// can be resolved to a function name before category lookup. Without this,
	// funcCategory["0x1234"] is always "" and hex VA targets are never matched.
	pcToName := map[string]string{}
	for _, f := range funcs {
		if f.PC != "" && f.Name != "" {
			pcToName[f.PC] = f.Name
		}
	}
	// Build call graph: caller → callees
	callerCallees := map[string]map[string]bool{}
	for _, e := range edges {
		if e.Target == "" {
			continue
		}
		// Resolve hex VA targets to their function name when possible.
		if strings.HasPrefix(e.Target, "0x") {
			if resolved, ok := pcToName[e.Target]; ok && resolved != "" {
				e.Target = resolved
			}
		}
		if callerCallees[e.FromFunc] == nil {
			callerCallees[e.FromFunc] = map[string]bool{}
		}
		callerCallees[e.FromFunc][e.Target] = true
	}

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
						Confidence: "medium",
					})
				}
			}
		}
	}

	// Pattern 2: credential → network (credential access followed by network send)
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
						Pattern:    "credential_to_network",
						Category:   "data_exfil",
						Functions:  []string{credFn, netFn},
						EdgeCount:  1,
						Confidence: "medium",
					})
				}
			}
		}
	}

	// Pattern 3: location → network (location access followed by network send)
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
						Pattern:    "location_to_network",
						Category:   "tracking",
						Functions:  []string{locFn, netFn},
						EdgeCount:  1,
						Confidence: "medium",
					})
				}
			}
		}
	}

	// Pattern 4: crypto → network (encryption followed by network send)
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
						Pattern:    "crypto_to_network",
						Category:   "encrypted_exfil",
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

	if len(findings) == 0 {
		return nil
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
	return writeJSONLFile(filepath.Join(outDir, "behavioral_findings.jsonl"), findings)
}

// Ensure disasm types are available for the function signatures.
