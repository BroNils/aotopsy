package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/signal"
)

// SARIF 2.1.0 types — subset sufficient for AOTopsy security findings.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0-os.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool      sarifTool       `json:"tool"`
	Artifacts []sarifArtifact `json:"artifacts,omitempty"`
	Results   []sarifResult   `json:"results"`
}

// sarifArtifact describes the analysed binary (SARIF 2.1.0 §3.24).
//
// Without it a consumer has a report about "libapp.so" with no way to
// tell which one: every Flutter app ships a file by that name.
type sarifArtifact struct {
	Location sarifArtifactLocation `json:"location"`
	Length   int64                 `json:"length,omitempty"`
	Roles    []string              `json:"roles,omitempty"`
	MIMEType string                `json:"mimeType,omitempty"`
	Hashes   map[string]string     `json:"hashes,omitempty"`
}

// sarifAddress locates a finding in a binary (SARIF 2.1.0 §3.32).
//
// This is where an address belongs. It used to live in a text snippet
// with region.startLine pinned to 1, which §3.30.21 forbids for a binary
// artifact -- and which meant every finding in the report pointed at
// "line 1" of a file that has no lines.
type sarifAddress struct {
	AbsoluteAddress uint64 `json:"absoluteAddress"`
	Kind            string `json:"kind,omitempty"`
	Name            string `json:"name,omitempty"`
	FullyQualified  string `json:"fullyQualifiedName,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifDescription  `json:"shortDescription"`
	FullDescription  *sarifDescription `json:"fullDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	DefaultConfig    sarifRuleConfig   `json:"defaultConfiguration"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifDescription struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifDescription  `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Address          *sarifAddress         `json:"address,omitempty"`
}

type sarifArtifactLocation struct {
	URI   string `json:"uri"`
	Index *int   `json:"index,omitempty"`
}

// These are report-family categories rather than ClassifyString categories.
// All ordinary signal-category severities come from signal.CategorySARIFLevel
// so JSON and SARIF cannot drift independently.
var reportOnlyRuleLevel = map[string]string{
	"entropy":     "note",
	"source_sink": "warning",
	"yara":        "warning",
	"behavioral":  "warning",
}

func sarifLevel(category string) string {
	if level := reportOnlyRuleLevel[category]; level != "" {
		return level
	}
	return signal.CategorySARIFLevel(category)
}

// findingSARIFLevel caps category impact by the producer's epistemic
// confidence. A high-impact category can describe what a confirmed behavior
// would mean, but a lexical or proximity heuristic must not become an
// error-level assertion merely because its category is severe.
func findingSARIFLevel(category, confidence string) string {
	base := sarifLevel(category)
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high", "exact":
		return base
	case "medium":
		if base == "error" {
			return "warning"
		}
		return base
	case "low", "info", "heuristic":
		return "note"
	case "":
		// Missing confidence is missing evidence metadata, not permission to
		// inherit the category's maximum impact. Producers must opt into stronger
		// result levels with an explicit confidence value.
		return "note"
	default:
		// Unknown producer vocabulary is not grounds to inflate certainty.
		return "note"
	}
}

// ruleDescription maps categories to human-readable descriptions.
var ruleDescription = map[string]string{
	"rooting":        "Root/jailbreak-related indicator",
	"anti_analysis":  "Anti-debugging, anti-frida, or emulator-related indicator",
	"ssl_pinning":    "SSL/TLS certificate-pinning-related indicator",
	"accessibility":  "Accessibility, input-observation, or screen-capture-related indicator",
	"fraud":          "Fraud, phishing, banking, or credential-related indicator",
	"dynamic_load":   "Dynamic-loading or reflection-related indicator",
	"ipc":            "Android IPC usage — Binder, ServiceManager, ContentProvider",
	"covert_channel": "Tor, proxy, tunneling, or covert-channel-related indicator",
	"drm":            "DRM or media-key-related indicator",
	"obfuscation":    "Identifier population is consistent with code obfuscation",
	"crypto_const":   "Distinctive cryptographic algorithm constant observed",
	"method_channel": "Flutter MethodChannel usage detected",
	"plugin":         "Flutter plugin integration detected",
	"url":            "URL reference detected",
	"host":           "Network host or IP literal detected",
	"file":           "File/path reference detected",
	"cloaking":       "Conditional-gating or redirect-related indicator",
	"async":          "SDK-defined async suspension/runtime behavior",
	"generator":      "SDK-defined generator suspension/runtime behavior",
	"encryption":     "Encryption-related lexical indicator",
	"auth":           "Authentication-related lexical indicator",
	"net":            "Network-related lexical indicator",
	"base64":         "Printable Base64 payload indicator",
	"sim":            "SIM or telephony-related indicator",
	"sms":            "SMS-related indicator",
	"contacts":       "Contacts or address-book-related indicator",
	"location":       "Location or GPS-related indicator",
	"device":         "Device-identification-related indicator",
	"data":           "Bulk-data-collection-related indicator",
	"camera":         "Camera-related indicator",
	"webview":        "WebView or JavaScript-bridge-related indicator",
	"blockchain":     "Blockchain or cryptocurrency-wallet-related indicator",
	"gambling":       "Gambling or betting-related indicator",
	"attribution":    "Install-attribution or campaign-tracking-related indicator",
	"entropy":        "High-entropy binary section observed; entropy alone does not identify packing or encryption",
	"source_sink":    "Sensitive-source and sink indicators occur in the same or nearby statically resolved functions",
	"yara":           "Security-oriented string rule matched recovered lexical evidence",
	"behavioral":     "Heuristic call-graph behavior pattern matched",
}

// SignalFinding is a single security finding from signal analysis.
type SignalFinding struct {
	Category           string `json:"category"`
	StringValue        string `json:"string_value"`
	Function           string `json:"function"`
	PC                 string `json:"pc"`
	AddressKind        string `json:"address_kind,omitempty"`
	RuleID             string `json:"rule_id,omitempty"`
	ProducerConfidence string `json:"producer_confidence,omitempty"`
	// FingerprintParts are stable, producer-owned identity components for
	// SARIF partialFingerprints. They deliberately exclude presentation text,
	// absolute addresses, confidence scores, and other values that can change
	// without changing the logical finding.
	FingerprintParts []string `json:"-"`
}

// ArtifactIdentity is immutable provenance captured when the input was opened.
// SARIF generation must never reopen a mutable source path and accidentally
// describe replacement bytes that were not the bytes actually analysed.
type ArtifactIdentity struct {
	URI    string `json:"uri"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

const sarifFindingFingerprintKey = "aotopsyFinding/v4"

type normalizedFinding struct {
	Category           string
	StringValue        string
	Function           string
	PC                 string
	AddressKind        string
	RuleID             string
	ProducerConfidence string
	FingerprintParts   []string
	Address            uint64
	HasAddress         bool
	identity           string
}

func describeArtifact(identity ArtifactIdentity) sarifArtifact {
	a := sarifArtifact{
		Location: sarifArtifactLocation{URI: "libapp.so"},
		Roles:    []string{"analysisTarget"},
		MIMEType: "application/x-sharedlib",
	}
	if identity.URI != "" {
		a.Location.URI = (&url.URL{Path: filepath.Base(identity.URI)}).EscapedPath()
	}
	if identity.Size > 0 {
		a.Length = identity.Size
	}
	if identity.SHA256 != "" {
		a.Hashes = map[string]string{"sha-256": strings.ToLower(identity.SHA256)}
	}
	return a
}

// parseAddress reads a "0x..." PC. Findings that carry no address at all
// (binary-level ones like entropy or obfuscation) get no address object
// rather than a fabricated zero.
func parseAddress(pc string) (uint64, bool) {
	s := strings.TrimSpace(pc)
	if s == "" {
		return 0, false
	}
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return 0, false
	}
	s = s[2:]
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func validateArtifactIdentity(identity ArtifactIdentity) error {
	if identity.Size < 0 {
		return fmt.Errorf("sarif: artifact size must not be negative")
	}
	if identity.SHA256 == "" {
		return nil
	}
	if len(identity.SHA256) != sha256.Size*2 {
		return fmt.Errorf("sarif: artifact sha256 has %d hex characters, want %d", len(identity.SHA256), sha256.Size*2)
	}
	if _, err := hex.DecodeString(identity.SHA256); err != nil {
		return fmt.Errorf("sarif: artifact sha256 is not hexadecimal: %w", err)
	}
	return nil
}

func normalizeFinding(f SignalFinding) (normalizedFinding, error) {
	n := normalizedFinding{
		Category:           strings.TrimSpace(f.Category),
		StringValue:        f.StringValue,
		Function:           f.Function,
		ProducerConfidence: strings.TrimSpace(f.ProducerConfidence),
		FingerprintParts:   f.FingerprintParts,
	}
	if n.Category == "" {
		return normalizedFinding{}, fmt.Errorf("empty category")
	}
	n.RuleID = strings.TrimSpace(f.RuleID)
	if n.RuleID == "" {
		n.RuleID = "signal.category." + n.Category
	}
	pc := strings.TrimSpace(f.PC)
	if pc != "" {
		addr, ok := parseAddress(pc)
		if !ok {
			return normalizedFinding{}, fmt.Errorf("invalid address %q", f.PC)
		}
		n.Address = addr
		n.HasAddress = true
		n.PC = fmt.Sprintf("0x%x", addr)
		n.AddressKind = strings.TrimSpace(f.AddressKind)
		if n.AddressKind == "" {
			n.AddressKind = "instruction"
		}
	}
	identityTuple := [7]string{
		n.RuleID,
		n.Category,
		n.Function,
		n.PC,
		n.StringValue,
		n.AddressKind,
		n.ProducerConfidence,
	}
	b, _ := json.Marshal(identityTuple)
	n.identity = string(b)
	return n, nil
}

// partialFingerprintIdentity intentionally excludes the absolute address and
// producer confidence. SARIF result management is expected to survive binary
// layout shifts, and Appendix B specifically warns against absolute binary
// locations in fingerprint computation. Confidence is result metadata rather
// than part of the finding's logical identity.
//
// Keep this separate from normalizedFinding.identity: the latter describes the
// exact emitted occurrence and is therefore still appropriate for exact
// deduplication within one report.
func partialFingerprintIdentity(f normalizedFinding) string {
	if len(f.FingerprintParts) > 0 {
		parts := make([]string, 0, len(f.FingerprintParts)+1)
		parts = append(parts, f.RuleID)
		parts = append(parts, f.FingerprintParts...)
		b, _ := json.Marshal(parts)
		return string(b)
	}
	b, _ := json.Marshal([5]string{
		f.RuleID,
		f.Category,
		f.Function,
		f.StringValue,
		f.AddressKind,
	})
	return string(b)
}

func findingMessage(f normalizedFinding) string {
	msg := fmt.Sprintf("%s: %q", f.Category, f.StringValue)
	if f.Function != "" {
		msg += " in " + f.Function
	}
	if f.PC != "" {
		msg += " at " + f.PC
	}
	return msg
}

// WriteSARIF writes a SARIF 2.1.0 report from signal findings.
//
// identity is captured provenance for the analysed binary. A zero identity
// still yields a valid report with a placeholder artifact name.
func WriteSARIF(dir string, findings []SignalFinding, toolVersion string, identity ArtifactIdentity) error {
	if err := validateArtifactIdentity(identity); err != nil {
		return err
	}
	normalized := make([]normalizedFinding, 0, len(findings))
	seenFindings := make(map[string]struct{}, len(findings))
	ruleCategory := make(map[string]string)
	for i, f := range findings {
		n, err := normalizeFinding(f)
		if err != nil {
			return fmt.Errorf("sarif: finding %d: %w", i, err)
		}
		if prior, ok := ruleCategory[n.RuleID]; ok && prior != n.Category {
			return fmt.Errorf("sarif: rule %q is used with conflicting categories %q and %q", n.RuleID, prior, n.Category)
		}
		ruleCategory[n.RuleID] = n.Category
		if _, duplicate := seenFindings[n.identity]; duplicate {
			continue
		}
		seenFindings[n.identity] = struct{}{}
		normalized = append(normalized, n)
	}
	sort.Slice(normalized, func(i, j int) bool {
		a, b := normalized[i], normalized[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.HasAddress != b.HasAddress {
			return !a.HasAddress
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		if a.Function != b.Function {
			return a.Function < b.Function
		}
		if a.StringValue != b.StringValue {
			return a.StringValue < b.StringValue
		}
		if a.AddressKind != b.AddressKind {
			return a.AddressKind < b.AddressKind
		}
		return a.ProducerConfidence < b.ProducerConfidence
	})

	ruleIDs := make([]string, 0, len(ruleCategory))
	for id := range ruleCategory {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		category := ruleCategory[ruleID]
		level := sarifLevel(category)
		desc := ruleDescription[category]
		if desc == "" {
			desc = "Security finding: " + category
		}
		rules = append(rules, sarifRule{
			ID:               ruleID,
			Name:             ruleID,
			ShortDescription: sarifDescription{Text: desc},
			HelpURI:          "https://github.com/BroNils/aotopsy",
			DefaultConfig:    sarifRuleConfig{Level: level},
			Properties:       map[string]string{"category": category},
		})
	}

	artifact := describeArtifact(identity)
	artifactIndex := 0

	// Build results
	results := make([]sarifResult, 0, len(normalized))
	for _, f := range normalized {
		level := findingSARIFLevel(f.Category, f.ProducerConfidence)
		loc := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{
					URI:   artifact.Location.URI,
					Index: &artifactIndex,
				},
			},
		}
		if f.HasAddress {
			loc.PhysicalLocation.Address = &sarifAddress{
				AbsoluteAddress: f.Address,
				Kind:            f.AddressKind,
				Name:            f.Function,
			}
		}
		result := sarifResult{
			RuleID:              f.RuleID,
			Level:               level,
			Message:             sarifDescription{Text: findingMessage(f)},
			Locations:           []sarifLocation{loc},
			PartialFingerprints: map[string]string{sarifFindingFingerprintKey: fingerprintIdentity(partialFingerprintIdentity(f))},
			Properties:          map[string]string{"category": f.Category},
		}
		if f.ProducerConfidence != "" {
			result.Properties["producerConfidence"] = f.ProducerConfidence
		}
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "AOTopsy",
					Version:        toolVersion,
					InformationURI: "https://github.com/BroNils/aotopsy",
					Rules:          rules,
				},
			},
			Artifacts: []sarifArtifact{artifact},
			Results:   results,
		}},
	}

	path := filepath.Join(dir, "aotopsy.sarif")
	return WriteAtomic(path, 0o644, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(log); err != nil {
			return fmt.Errorf("sarif: encode: %w", err)
		}
		return nil
	})
}

func findingFingerprint(f SignalFinding) string {
	n, err := normalizeFinding(f)
	if err != nil {
		// WriteSARIF rejects malformed findings. Keep this helper total for tests
		// and diagnostics by hashing the untrusted tuple without interpreting it.
		ruleID := strings.TrimSpace(f.RuleID)
		if ruleID == "" {
			ruleID = "signal.category." + strings.TrimSpace(f.Category)
		}
		kind := strings.TrimSpace(f.AddressKind)
		pc := strings.TrimSpace(f.PC)
		if pc == "" {
			kind = ""
		}
		b, _ := json.Marshal([5]string{ruleID, strings.TrimSpace(f.Category), f.Function, f.StringValue, kind})
		return fingerprintIdentity(string(b))
	}
	return fingerprintIdentity(partialFingerprintIdentity(n))
}

func fingerprintIdentity(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}
