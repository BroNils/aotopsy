package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
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
	"entropy":    "warning",
	"taint":      "warning",
	"yara":       "error",
	"behavioral": "warning",
}

func sarifLevel(category string) string {
	if level := reportOnlyRuleLevel[category]; level != "" {
		return level
	}
	return signal.CategorySARIFLevel(category)
}

// ruleDescription maps categories to human-readable descriptions.
var ruleDescription = map[string]string{
	"rooting":        "Root/jailbreak detection or bypass code found",
	"anti_analysis":  "Anti-debugging, anti-frida, or emulator detection found",
	"ssl_pinning":    "SSL/TLS certificate pinning implementation detected",
	"accessibility":  "Accessibility service abuse — potential keylogger or screen capture",
	"fraud":          "Fraud, phishing, or banking-related patterns detected",
	"dynamic_load":   "Dynamic code loading via DynamicLibrary or reflection",
	"ipc":            "Android IPC usage — Binder, ServiceManager, ContentProvider",
	"covert_channel": "Covert communication channel — Tor, proxy, DNS tunnel",
	"drm_bypass":     "DRM bypass or circumvention code detected",
	"obfuscation":    "Code obfuscation detected — short meaningless identifiers",
	"crypto_const":   "Known cryptographic algorithm constants detected",
	"method_channel": "Flutter MethodChannel usage detected",
	"plugin":         "Flutter plugin integration detected",
	"url":            "URL reference detected",
	"host":           "Network host or IP literal detected",
	"file":           "File/path reference detected",
	"cloaking":       "Conditional cloaking or redirect behavior detected",
	"thr":            "Interesting Dart Thread/runtime call detected",
	"async":          "Async/generator runtime behavior detected",
	"generator":      "Generator suspension/runtime behavior detected",
	"encryption":     "Encryption-related keyword detected",
	"auth":           "Authentication-related keyword detected",
	"net":            "Network communication detected",
	"base64":         "High-entropy string — potential API key or secret",
	"sim":            "SIM card or telephony access",
	"sms":            "SMS read or send capability",
	"contacts":       "Contact list access",
	"location":       "Location or GPS access",
	"device":         "Device fingerprinting or identification",
	"data":           "Bulk data collection pattern",
	"camera":         "Camera access",
	"webview":        "WebView usage with JavaScript bridge",
	"blockchain":     "Blockchain or cryptocurrency wallet",
	"gambling":       "Gambling or betting patterns",
	"attribution":    "Install attribution or campaign tracking",
	"entropy":        "High-entropy or packed/encrypted binary section detected",
	"taint":          "Potential sensitive-data source-to-sink flow detected",
	"yara":           "Malware-oriented rule matched recovered program evidence",
	"behavioral":     "Suspicious call-graph behavioral pattern detected",
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
}

// ArtifactIdentity is immutable provenance captured when the input was opened.
// SARIF generation must never reopen a mutable source path and accidentally
// describe replacement bytes that were not the bytes actually analysed.
type ArtifactIdentity struct {
	URI    string `json:"uri"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

const sarifFindingFingerprintKey = "aotopsyFinding/v2"

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

// WriteSARIF writes a SARIF 2.1.0 report from signal findings.
//
// identity is captured provenance for the analysed binary. A zero identity
// still yields a valid report with a placeholder artifact name.
func WriteSARIF(dir string, findings []SignalFinding, toolVersion string, identity ArtifactIdentity) error {
	if err := validateArtifactIdentity(identity); err != nil {
		return err
	}
	for i, f := range findings {
		if strings.TrimSpace(f.Category) == "" {
			return fmt.Errorf("sarif: finding %d has empty category", i)
		}
		if strings.TrimSpace(f.PC) != "" {
			if _, ok := parseAddress(f.PC); !ok {
				return fmt.Errorf("sarif: finding %d has invalid address %q", i, f.PC)
			}
		}
	}
	// Build unique rules from findings
	ruleSet := map[string]bool{}
	rules := make([]sarifRule, 0)
	for _, f := range findings {
		if ruleSet[f.Category] {
			continue
		}
		ruleSet[f.Category] = true
		level := sarifLevel(f.Category)
		desc := ruleDescription[f.Category]
		if desc == "" {
			desc = "Security finding: " + f.Category
		}
		rules = append(rules, sarifRule{
			ID:               "AOTOPSY_" + f.Category,
			Name:             f.Category,
			ShortDescription: sarifDescription{Text: desc},
			HelpURI:          "https://github.com/BroNils/aotopsy",
			DefaultConfig:    sarifRuleConfig{Level: level},
			Properties:       map[string]string{"category": f.Category},
		})
	}

	artifact := describeArtifact(identity)
	artifactIndex := 0

	// Build results
	results := make([]sarifResult, 0)
	for _, f := range findings {
		level := sarifLevel(f.Category)
		loc := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{
					URI:   artifact.Location.URI,
					Index: &artifactIndex,
				},
			},
		}
		if addr, ok := parseAddress(f.PC); ok {
			kind := f.AddressKind
			if kind == "" {
				kind = "instruction"
			}
			loc.PhysicalLocation.Address = &sarifAddress{
				AbsoluteAddress: addr,
				Kind:            kind,
				Name:            f.Function,
			}
		}
		results = append(results, sarifResult{
			RuleID: "AOTOPSY_" + f.Category,
			Level:  level,
			Message: sarifDescription{
				Text: fmt.Sprintf("%s: %q in %s at %s", f.Category, f.StringValue, f.Function, f.PC),
			},
			Locations:           []sarifLocation{loc},
			PartialFingerprints: map[string]string{sarifFindingFingerprintKey: findingFingerprint(f)},
		})
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
	// JSON's array framing is injective for strings, unlike colon joining where
	// field-boundary shifts can map distinct findings to the same byte sequence.
	pc := strings.TrimSpace(f.PC)
	kind := f.AddressKind
	if addr, ok := parseAddress(pc); ok {
		pc = fmt.Sprintf("0x%x", addr)
		if kind == "" {
			kind = "instruction"
		}
	} else if pc == "" {
		// AddressKind has no effect on the emitted SARIF when there is no
		// address, so it must not perturb the identity of that result.
		kind = ""
	}
	b, _ := json.Marshal([5]string{f.Category, f.Function, pc, f.StringValue, kind})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
