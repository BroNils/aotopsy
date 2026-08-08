package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/signal"
)

// SARIF 2.1.0 types — subset sufficient for AOTopsy security findings.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0-os.html

type sarifLog struct {
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
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
	FullDescription  sarifDescription  `json:"fullDescription,omitempty"`
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
	RuleID          string          `json:"ruleId"`
	Level           string          `json:"level"`
	Message         sarifDescription `json:"message"`
	Locations       []sarifLocation  `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
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
	StartLine   int    `json:"startLine"`
	StartColumn int    `json:"startColumn,omitempty"`
	Snippet     sarifSnippet `json:"snippet,omitempty"`
}

type sarifSnippet struct {
	Text string `json:"text"`
}

// ruleLevel maps signal categories to SARIF severity levels.
var ruleLevel = map[string]string{
	signal.CatRooting:       "error",
	signal.CatAntiAnalysis:  "error",
	signal.CatSSLPinning:    "warning",
	signal.CatAccessibility: "error",
	signal.CatFraud:         "error",
	signal.CatDynamicLoad:   "warning",
	signal.CatIPC:           "note",
	signal.CatCovertChannel: "error",
	signal.CatDRMBypass:     "warning",
	signal.CatObfuscation:   "warning",
	signal.CatCryptoConst:   "note",
	signal.CatMethodChannel: "note",
	signal.CatPlugin:        "note",
	signal.CatEncryption:    "note",
	signal.CatAuth:          "note",
	signal.CatNet:           "note",
	signal.CatBase64Key:     "warning",
	signal.CatSIM:           "warning",
	signal.CatSMS:           "warning",
	signal.CatContacts:      "warning",
	signal.CatLocation:      "warning",
	signal.CatDeviceInfo:    "warning",
	signal.CatDataCollect:   "warning",
	signal.CatCamera:        "warning",
	signal.CatWebView:       "note",
	signal.CatBlockchain:    "note",
	signal.CatGambling:      "note",
	signal.CatAttribution:   "note",
}

// ruleDescription maps categories to human-readable descriptions.
var ruleDescription = map[string]string{
	signal.CatRooting:       "Root/jailbreak detection or bypass code found",
	signal.CatAntiAnalysis:  "Anti-debugging, anti-frida, or emulator detection found",
	signal.CatSSLPinning:    "SSL/TLS certificate pinning implementation detected",
	signal.CatAccessibility: "Accessibility service abuse — potential keylogger or screen capture",
	signal.CatFraud:         "Fraud, phishing, or banking-related patterns detected",
	signal.CatDynamicLoad:   "Dynamic code loading via DynamicLibrary or reflection",
	signal.CatIPC:           "Android IPC usage — Binder, ServiceManager, ContentProvider",
	signal.CatCovertChannel: "Covert communication channel — Tor, proxy, DNS tunnel",
	signal.CatDRMBypass:     "DRM bypass or circumvention code detected",
	signal.CatObfuscation:   "Code obfuscation detected — short meaningless identifiers",
	signal.CatCryptoConst:   "Known cryptographic algorithm constants detected",
	signal.CatMethodChannel: "Flutter MethodChannel usage detected",
	signal.CatPlugin:        "Flutter plugin integration detected",
	signal.CatEncryption:    "Encryption-related keyword detected",
	signal.CatAuth:          "Authentication-related keyword detected",
	signal.CatNet:           "Network communication detected",
	signal.CatBase64Key:     "High-entropy string — potential API key or secret",
	signal.CatSIM:           "SIM card or telephony access",
	signal.CatSMS:           "SMS read or send capability",
	signal.CatContacts:      "Contact list access",
	signal.CatLocation:      "Location or GPS access",
	signal.CatDeviceInfo:    "Device fingerprinting or identification",
	signal.CatDataCollect:   "Bulk data collection pattern",
	signal.CatCamera:        "Camera access",
	signal.CatWebView:       "WebView usage with JavaScript bridge",
	signal.CatBlockchain:    "Blockchain or cryptocurrency wallet",
	signal.CatGambling:      "Gambling or betting patterns",
	signal.CatAttribution:   "Install attribution or campaign tracking",
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
							Snippet: sarifSnippet{
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
