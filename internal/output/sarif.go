package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	AbsoluteAddress int64  `json:"absoluteAddress"`
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

// ruleLevel maps signal categories to SARIF severity levels.
// Category strings are duplicated from signal/classify.go to keep output
// independent of the signal package.
var ruleLevel = map[string]string{
	"rooting":        "error",
	"anti_analysis":  "error",
	"ssl_pinning":    "warning",
	"accessibility":  "error",
	"fraud":          "error",
	"dynamic_load":   "warning",
	"ipc":            "note",
	"covert_channel": "error",
	"drm_bypass":     "warning",
	"obfuscation":    "warning",
	"crypto_const":   "note",
	"method_channel": "note",
	"plugin":         "note",
	"encryption":     "note",
	"auth":           "note",
	"net":            "note",
	"base64":         "warning",
	"sim":            "warning",
	"sms":            "warning",
	"contacts":       "warning",
	"location":       "warning",
	"device":         "warning",
	"data":           "warning",
	"camera":         "warning",
	"webview":        "note",
	"blockchain":     "note",
	"gambling":       "note",
	"attribution":    "note",
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
}

// SignalFinding is a single security finding from signal analysis.
type SignalFinding struct {
	Category    string `json:"category"`
	StringValue string `json:"string_value"`
	Function    string `json:"function"`
	PC          string `json:"pc"`
}

// describeArtifact builds the run.artifacts entry for the analysed
// binary, hashing it so a report can be tied to the exact file.
func describeArtifact(libPath string) sarifArtifact {
	a := sarifArtifact{
		Location: sarifArtifactLocation{URI: "libapp.so"},
		Roles:    []string{"analysisTarget"},
		MIMEType: "application/x-sharedlib",
	}
	if libPath == "" {
		return a
	}
	a.Location.URI = filepath.Base(libPath)
	fi, err := os.Stat(libPath)
	if err != nil {
		return a
	}
	a.Length = fi.Size()
	f, err := os.Open(libPath)
	if err != nil {
		return a
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return a
	}
	a.Hashes = map[string]string{"sha-256": hex.EncodeToString(h.Sum(nil))}
	return a
}

// parseAddress reads a "0x..." PC. Findings that carry no address at all
// (binary-level ones like entropy or obfuscation) get no address object
// rather than a fabricated zero.
func parseAddress(pc string) (int64, bool) {
	s := strings.TrimSpace(pc)
	if s == "" {
		return 0, false
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	v, err := strconv.ParseInt(s, 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// WriteSARIF writes a SARIF 2.1.0 report from signal findings.
//
// libPath is the analysed binary; it names the artifact and supplies its
// size and SHA-256 so a report can be tied to the exact file it came
// from. Passing "" still writes a valid report, with the artifact
// described only by the placeholder name.
func WriteSARIF(dir string, findings []SignalFinding, toolVersion, libPath string) error {
	// Build unique rules from findings
	ruleSet := map[string]bool{}
	var rules []sarifRule
	for _, f := range findings {
		if ruleSet[f.Category] {
			continue
		}
		ruleSet[f.Category] = true
		level := ruleLevel[f.Category]
		if level == "" {
			level = "note"
		}
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

	artifact := describeArtifact(libPath)
	artifactIndex := 0

	// Build results
	var results []sarifResult
	for _, f := range findings {
		level := ruleLevel[f.Category]
		if level == "" {
			level = "note"
		}
		loc := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{
					URI:   artifact.Location.URI,
					Index: &artifactIndex,
				},
			},
		}
		if addr, ok := parseAddress(f.PC); ok {
			loc.PhysicalLocation.Address = &sarifAddress{
				AbsoluteAddress: addr,
				Kind:            "function",
				Name:            f.Function,
			}
		}
		results = append(results, sarifResult{
			RuleID: "AOTOPSY_" + f.Category,
			Level:  level,
			Message: sarifDescription{
				Text: fmt.Sprintf("%s: %q in %s at %s", f.Category, f.StringValue, f.Function, f.PC),
			},
			Locations: []sarifLocation{loc},
			PartialFingerprints: map[string]string{
				// Function and PC alone collide for binary-level findings,
				// which carry neither: every obfuscation finding hashed to
				// ":". The category and the matched string disambiguate.
				"aotopsyFindingV1": fmt.Sprintf("%s:%s:%s:%s",
					f.Category, f.Function, f.PC, f.StringValue),
			},
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
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("sarif: create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("sarif: encode: %w", err)
	}
	return nil
}
