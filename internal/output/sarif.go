package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// SARIF 2.1.0 types — subset sufficient for AOTopsy security findings.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0-os.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string       `json:"name"`
	Version        string       `json:"version"`
	InformationURI string       `json:"informationUri"`
	Rules          []sarifRule  `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifDescription  `json:"shortDescription"`
	HelpURI          string            `json:"helpUri"`
	DefaultConfig    sarifRuleConfig   `json:"defaultConfiguration"`
	Properties       map[string]string `json:"properties"`
}

type sarifDescription struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID             string            `json:"ruleId"`
	Level              string            `json:"level"`
	Message            sarifDescription  `json:"message"`
	Locations          []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int          `json:"startLine"`
	Snippet   *sarifSnippet `json:"snippet,omitempty"`
}

type sarifSnippet struct {
	Text string `json:"text"`
}

// ruleLevel maps signal categories to SARIF severity levels.
// Category strings are duplicated from signal/classify.go to keep output
// independent of the signal package.
var ruleLevel = map[string]string{
	"rooting":         "error",
	"anti_analysis":   "error",
	"ssl_pinning":     "warning",
	"accessibility":   "error",
	"fraud":           "error",
	"dynamic_load":    "warning",
	"ipc":             "note",
	"covert_channel":  "error",
	"drm_bypass":      "warning",
	"obfuscation":     "warning",
	"crypto_const":    "note",
	"method_channel":  "note",
	"plugin":          "note",
	"encryption":      "note",
	"auth":            "note",
	"net":             "note",
	"base64":          "warning",
	"sim":             "warning",
	"sms":             "warning",
	"contacts":        "warning",
	"location":        "warning",
	"device":          "warning",
	"data":            "warning",
	"camera":          "warning",
	"webview":         "note",
	"blockchain":      "note",
	"gambling":        "note",
	"attribution":     "note",
}

// ruleDescription maps categories to human-readable descriptions.
var ruleDescription = map[string]string{
	"rooting":         "Root/jailbreak detection or bypass code found",
	"anti_analysis":   "Anti-debugging, anti-frida, or emulator detection found",
	"ssl_pinning":     "SSL/TLS certificate pinning implementation detected",
	"accessibility":   "Accessibility service abuse — potential keylogger or screen capture",
	"fraud":           "Fraud, phishing, or banking-related patterns detected",
	"dynamic_load":    "Dynamic code loading via DynamicLibrary or reflection",
	"ipc":             "Android IPC usage — Binder, ServiceManager, ContentProvider",
	"covert_channel":  "Covert communication channel — Tor, proxy, DNS tunnel",
	"drm_bypass":      "DRM bypass or circumvention code detected",
	"obfuscation":     "Code obfuscation detected — short meaningless identifiers",
	"crypto_const":    "Known cryptographic algorithm constants detected",
	"method_channel":  "Flutter MethodChannel usage detected",
	"plugin":          "Flutter plugin integration detected",
	"encryption":      "Encryption-related keyword detected",
	"auth":            "Authentication-related keyword detected",
	"net":             "Network communication detected",
	"base64":          "High-entropy string — potential API key or secret",
	"sim":             "SIM card or telephony access",
	"sms":             "SMS read or send capability",
	"contacts":        "Contact list access",
	"location":        "Location or GPS access",
	"device":          "Device fingerprinting or identification",
	"data":            "Bulk data collection pattern",
	"camera":          "Camera access",
	"webview":         "WebView usage with JavaScript bridge",
	"blockchain":      "Blockchain or cryptocurrency wallet",
	"gambling":        "Gambling or betting patterns",
	"attribution":     "Install attribution or campaign tracking",
}

// SignalFinding is a single security finding from signal analysis.
type SignalFinding struct {
	Category    string `json:"category"`
	StringValue string `json:"string_value"`
	Function    string `json:"function"`
	PC          string `json:"pc"`
}

// WriteSARIF writes a SARIF 2.1.0 report from signal findings.
func WriteSARIF(dir string, findings []SignalFinding, toolVersion string) error {
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

	// Build results
	var results []sarifResult
	for _, f := range findings {
		level := ruleLevel[f.Category]
		if level == "" {
			level = "note"
		}
		results = append(results, sarifResult{
			RuleID: "AOTOPSY_" + f.Category,
			Level:  level,
			Message: sarifDescription{
				Text: fmt.Sprintf("%s: \"%s\" in %s", f.Category, f.StringValue, f.Function),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: "libapp.so",
						},
						Region: sarifRegion{
							StartLine: 1,
							Snippet: &sarifSnippet{
								Text: fmt.Sprintf("Function: %s at %s — String: %q", f.Function, f.PC, f.StringValue),
							},
						},
					},
				},
			},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": fmt.Sprintf("%s:%s", f.Function, f.PC),
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
			Results: results,
		}},
	}

	path := filepath.Join(dir, "report.sarif")
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
