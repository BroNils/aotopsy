package signal

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CryptoAlgorithmID identifies crypto algorithms from pool immediate values.
// Each constant is mapped to its algorithm name for reporting.
var cryptoAlgorithmID = map[string]string{
	// SHA-256
	"0x428a2f98": "SHA-256 K[0]", "0x71374491": "SHA-256 K[1]",
	"0xb5c0fbcf": "SHA-256 K[2]", "0xe9b5dba5": "SHA-256 K[3]",
	"0x3956c25b": "SHA-256 K[4]", "0x59f111f1": "SHA-256 K[5]",
	"0x923f82a4": "SHA-256 K[6]", "0xab1c5ed5": "SHA-256 K[7]",
	"0x6a09e667": "SHA-256 H[0]", "0xbb67ae85": "SHA-256 H[1]",
	"0x3c6ef372": "SHA-256 H[2]", "0xa54ff53a": "SHA-256 H[3]",
	"0x510e527f": "SHA-256 H[4]", "0x9b05688c": "SHA-256 H[5]",
	"0x1f83d9ab": "SHA-256 H[6]", "0x5be0cd19": "SHA-256 H[7]",
	// SHA-1
	"0x5a827999": "SHA-1 K[0]", "0x6ed9eba1": "SHA-1 K[1]",
	"0x8f1bbcdc": "SHA-1 K[2]", "0xca62c1d6": "SHA-1 K[3]",
	"0x67452301": "SHA-1 H[0]", "0xefcdab89": "SHA-1 H[1]",
	"0x98badcfe": "SHA-1 H[2]", "0x10325476": "SHA-1 H[3]",
	"0xc3d2e1f0": "SHA-1 H[4]",
	// MD5
	"0xd76aa478": "MD5 T[0]", "0xe8c7b756": "MD5 T[1]",
	"0x242070db": "MD5 T[2]", "0xc1bdceee": "MD5 T[3]",
	// AES S-box (first 4 entries as 32-bit words)
	"0x637c777b": "AES S-box[0-3]", "0x7b777c63": "AES S-box[4-7]",
	"0xf2b8669f": "AES S-box[8-11]", "0x6dc9a7b6": "AES S-box[12-15]",
	// AES Rcon
	"0x01000000": "AES Rcon[0]", "0x02000000": "AES Rcon[1]",
	"0x04000000": "AES Rcon[2]", "0x08000000": "AES Rcon[3]",
	"0x10000000": "AES Rcon[4]", "0x20000000": "AES Rcon[5]",
	"0x40000000": "AES Rcon[6]", "0x80000000": "AES Rcon[7]",
	"0x1b000000": "AES Rcon[8]", "0x36000000": "AES Rcon[9]",
	// ChaCha20 constants ("expand 32-byte k")
	"0x61707865": "ChaCha20 'expa'", "0x3320646e": "ChaCha20 'nd 3'",
	"0x79622d32": "ChaCha20 '2-by'", "0x6b206574": "ChaCha20 'te k'",
	// CRC32
	"0xedb88320": "CRC32 poly (reflected)", "0x04c11db7": "CRC32 poly (direct)",
	"0x82f63b78": "CRC32C poly (reflected)",
	// BLAKE2b IV
	"0x243f6a88": "BLAKE2b IV[0] / Blowfish P[0]",
	"0x85a308d3": "BLAKE2b IV[1] / Blowfish P[1]",
	"0x13198a2e": "BLAKE2b IV[2] / Blowfish P[2]",
	"0x03707344": "BLAKE2b IV[3] / Blowfish P[3]",
	// XTEA delta
	"0x9e3779b9": "XTEA/TEA delta (golden ratio)",
	// SHA-512
	"0x428a2f98d728ae22": "SHA-512 K[0]", "0x7137449123ef65cd": "SHA-512 K[1]",
	"0xb5c0fbcfec4d3b2f": "SHA-512 K[2]", "0xe9b5dba58189dbbc": "SHA-512 K[3]",
	"0x6a09e667f3bcc908": "SHA-512 H[0]", "0xbb67ae8584caa73b": "SHA-512 H[1]",
	"0x3c6ef372fe94f82b": "SHA-512 H[2]", "0xa54ff53a5f1d36f1": "SHA-512 H[3]",
	// Keccak round constants
	"0x0000000000000001": "Keccak RC[0]", "0x0000000000008082": "Keccak RC[1]",
	"0x800000000000808a": "Keccak RC[2]", "0x8000000080008000": "Keccak RC[3]",
}

// PoolImmediateRecord is a single pool immediate entry from pool_immediates.jsonl.
type PoolImmediateRecord struct {
	Index int    `json:"index"`
	Value int64  `json:"value"`
	Hex   string `json:"hex"`
}

// CryptoFinding is a crypto algorithm identification finding.
type CryptoFinding struct {
	Algorithm  string `json:"algorithm"`
	Constant   string `json:"constant"`
	PoolIndex  int    `json:"pool_index"`
	Value      string `json:"value"`
}

// IdentifyCryptoFromPoolImmediates reads pool_immediates.jsonl and identifies
// crypto algorithm constants. Returns a list of findings.
func IdentifyCryptoFromPoolImmediates(inDir string) ([]CryptoFinding, error) {
	path := filepath.Join(inDir, "pool_immediates.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, nil // not fatal — file may not exist
	}
	defer func() { _ = f.Close() }()

	var findings []CryptoFinding
	dec := json.NewDecoder(f)
	for dec.More() {
		var rec PoolImmediateRecord
		if err := dec.Decode(&rec); err != nil {
			break
		}
		hex := strings.ToLower(rec.Hex)
		if algo, ok := cryptoAlgorithmID[hex]; ok {
			findings = append(findings, CryptoFinding{
				Algorithm: algo,
				Constant:  hex,
				PoolIndex: rec.Index,
				Value:     rec.Hex,
			})
		}
	}
	return findings, nil
}

// IdentifyCryptoFromBinary scans the raw ELF binary for crypto constant bytes.
// Dart AOT compiles integer constants to MOVZ/MOVK instructions (ARM64) or
// MOV imm (x86_64), so they appear as raw bytes in the .text section, not
// as pool immediates. This function scans for 32-bit and 64-bit little-endian
// representations of known crypto constants.
func IdentifyCryptoFromBinary(libPath string) ([]CryptoFinding, error) {
	data, err := os.ReadFile(libPath)
	if err != nil {
		return nil, err
	}

	var findings []CryptoFinding
	seen := map[string]bool{} // dedup by algorithm+constant

	// Build a lookup: hex string → algorithm name
	// Also build byte patterns for searching
	type cryptoPattern struct {
		algo string
		hex  string
		bytes []byte
	}
	var patterns []cryptoPattern
	for hex, algo := range cryptoAlgorithmID {
		// Parse hex to bytes
		var val uint64
		if _, err := fmt.Sscanf(hex, "0x%x", &val); err != nil {
			continue
		}
		// Determine search width from the HEX STRING length, not the runtime
		// value. A constant declared as 16 hex digits (e.g. "0x0000000000000001",
		// Keccak RC[0]) is a 64-bit constant and must be searched as 8-byte LE,
		// even though its value (1) fits in 32 bits. Searching it as 4-byte LE
		// ("01 00 00 00") matches millions of unrelated bytes (every `MOV X0, #1`,
		// boolean true, array length 1) and floods findings with false positives.
		// A constant declared as <=8 hex digits is a genuine 32-bit constant.
		hexDigits := len(strings.TrimPrefix(hex, "0x"))
		is64Bit := hexDigits > 8
		if !is64Bit && val <= 0xFFFFFFFF {
			// 32-bit constant: search as 4-byte LE
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(val))
			patterns = append(patterns, cryptoPattern{algo: algo, hex: hex, bytes: buf})
		} else {
			// 64-bit constant: search as 8-byte LE
			buf := make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, val)
			patterns = append(patterns, cryptoPattern{algo: algo, hex: hex, bytes: buf})
		}
	}

	// Scan binary for each pattern
	for _, pat := range patterns {
		offset := 0
		for {
			idx := bytes.Index(data[offset:], pat.bytes)
			if idx < 0 {
				break
			}
			absOffset := offset + idx
			key := pat.algo + ":" + pat.hex
			if !seen[key] {
				seen[key] = true
				findings = append(findings, CryptoFinding{
					Algorithm:  pat.algo,
					Constant:   pat.hex,
					PoolIndex:  -1, // not from pool — from binary
					Value:      fmt.Sprintf("binary_offset=0x%x", absOffset),
				})
			}
			offset = absOffset + len(pat.bytes)
		}
	}

	return findings, nil
}

// MethodChannelFinding is a Flutter MethodChannel enumeration finding.
type MethodChannelFinding struct {
	Channel string `json:"channel"`
	Func    string `json:"func,omitempty"`
}

var methodChannelRe = regexp.MustCompile(`MethodChannel\s*\(\s*["']([^"']+)["']\s*\)`)

// EnumerateMethodChannels scans string refs for MethodChannel("name") patterns
// and also detects Flutter platform channel names by pattern matching.
func EnumerateMethodChannels(stringRefs []StringRefRecord) []MethodChannelFinding {
	var findings []MethodChannelFinding
	seen := map[string]bool{}
	for _, sr := range stringRefs {
		if sr.Value == "" {
			continue
		}
		// Pattern 1: MethodChannel("name") — Dart source pattern
		matches := methodChannelRe.FindStringSubmatch(sr.Value)
		if len(matches) >= 2 {
			channel := matches[1]
			if !seen[channel] {
				seen[channel] = true
				findings = append(findings, MethodChannelFinding{
					Channel: channel,
					Func:    sr.Func,
				})
			}
			continue
		}
		// Pattern 2: Explicit MethodChannel references
		if strings.Contains(sr.Value, "methodChannel") || strings.Contains(sr.Value, "MethodChannel") {
			if !seen[sr.Value] && len(sr.Value) > 5 && len(sr.Value) < 200 {
				seen[sr.Value] = true
				findings = append(findings, MethodChannelFinding{
					Channel: sr.Value,
					Func:    sr.Func,
				})
			}
			continue
		}
		// Pattern 3: Flutter platform channel naming convention
		// Channels like "dev.flutter/channel-buffers", "flutter/platform", etc.
		if (strings.Contains(sr.Value, "dev.flutter/") ||
			strings.Contains(sr.Value, "flutter/platform") ||
			strings.Contains(sr.Value, "flutter/navigation") ||
			strings.Contains(sr.Value, "flutter/textinput") ||
			strings.Contains(sr.Value, "flutter/keyevent") ||
			strings.Contains(sr.Value, "flutter/accessibility") ||
			strings.Contains(sr.Value, "flutter/system") ||
			strings.Contains(sr.Value, "flutter/localization") ||
			strings.Contains(sr.Value, "flutter/sensors") ||
			strings.Contains(sr.Value, "flutter/settings") ||
			strings.Contains(sr.Value, "flutter/lifecycle")) &&
			!seen[sr.Value] {
			seen[sr.Value] = true
			findings = append(findings, MethodChannelFinding{
				Channel: sr.Value,
				Func:    sr.Func,
			})
		}
		// Pattern 4: BinaryMessenger / platform channel infrastructure
		if strings.Contains(sr.Value, "BinaryMessenger") ||
			strings.Contains(sr.Value, "PlatformChannel") ||
			strings.Contains(sr.Value, "BasicMessageChannel") {
			if !seen[sr.Value] {
				seen[sr.Value] = true
				findings = append(findings, MethodChannelFinding{
					Channel: sr.Value,
					Func:    sr.Func,
				})
			}
		}
	}
	return findings
}

// PluginFinding is a Flutter plugin enumeration finding.
type PluginFinding struct {
	Plugin string `json:"plugin"`
	Func   string `json:"func,omitempty"`
}

// Known Flutter plugin package name patterns.
var pluginPatterns = []string{
	"flutter_plugin_", "_plugin", "plugin_android", "plugin_ios",
	"MissingPluginException", "package:", "video_player", "path_provider",
	"shared_preferences", "url_launcher", "image_picker", "file_picker",
	"camera", "geolocator", "permission_handler", "firebase_",
	"google_maps", "webview", "local_auth", "connectivity",
	"device_info", "package_info", "flutter_local_notifications",
	"flutter_push", "jpush", "umeng", "tencent_", "aliyun_",
	"bytedance_", "huawei_", "xiaomi_", "PluginRegistry", "FlutterPlugin",
}

// EnumeratePlugins scans string refs for Flutter plugin package names.
func EnumeratePlugins(stringRefs []StringRefRecord) []PluginFinding {
	var findings []PluginFinding
	seen := map[string]bool{}
	for _, sr := range stringRefs {
		if sr.Value == "" {
			continue
		}
		val := strings.ToLower(sr.Value)
		for _, pat := range pluginPatterns {
			if strings.Contains(val, pat) {
				if !seen[sr.Value] {
					seen[sr.Value] = true
					findings = append(findings, PluginFinding{
						Plugin: sr.Value,
						Func:   sr.Func,
					})
				}
				break
			}
		}
	}
	return findings
}

// NetworkEndpointFinding is a network endpoint extraction finding.
type NetworkEndpointFinding struct {
	Type    string `json:"type"` // "url", "ip", "domain"
	Value   string `json:"value"`
	Func    string `json:"func,omitempty"`
}

var (
	urlRe      = regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
	ipRe       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	domainRe   = regexp.MustCompile(`\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b`)
)

// ExtractNetworkEndpoints scans string refs for URLs, IPs, and domains.
func ExtractNetworkEndpoints(stringRefs []StringRefRecord) []NetworkEndpointFinding {
	var findings []NetworkEndpointFinding
	seen := map[string]bool{}
	for _, sr := range stringRefs {
		if sr.Value == "" || len(sr.Value) < 4 {
			continue
		}
		// URLs
		for _, m := range urlRe.FindAllString(sr.Value, -1) {
			key := "url:" + m
			if !seen[key] {
				seen[key] = true
				findings = append(findings, NetworkEndpointFinding{
					Type:  "url",
					Value: m,
					Func:  sr.Func,
				})
			}
		}
		// IPs (skip 0.0.0.0, 127.0.0.1, 255.x)
		for _, m := range ipRe.FindAllString(sr.Value, -1) {
			if m == "0.0.0.0" || m == "127.0.0.1" || strings.HasPrefix(m, "255.") {
				continue
			}
			key := "ip:" + m
			if !seen[key] {
				seen[key] = true
				findings = append(findings, NetworkEndpointFinding{
					Type:  "ip",
					Value: m,
					Func:  sr.Func,
				})
			}
		}
		// Domains (must have at least one dot, not start with a number)
		for _, m := range domainRe.FindAllString(sr.Value, -1) {
			if len(m) < 5 || m[0] >= '0' && m[0] <= '9' {
				continue
			}
			// Skip common false positives
			lower := strings.ToLower(m)
			if strings.Contains(lower, ".dart") || strings.Contains(lower, ".go") ||
				strings.Contains(lower, ".json") || strings.Contains(lower, ".txt") ||
				strings.Contains(lower, ".png") || strings.Contains(lower, ".jpg") ||
				strings.Contains(lower, ".class") || strings.Contains(lower, ".java") ||
				strings.Contains(lower, ".xml") || strings.Contains(lower, ".so") ||
				strings.Contains(lower, ".h") || strings.Contains(lower, ".c") ||
				strings.Contains(lower, ".cc") || strings.Contains(lower, ".cpp") ||
				strings.Contains(lower, ".py") || strings.Contains(lower, ".js") ||
				strings.Contains(lower, ".ts") || strings.Contains(lower, ".html") ||
				strings.Contains(lower, ".css") || strings.Contains(lower, ".md") ||
				strings.Contains(lower, ".yaml") || strings.Contains(lower, ".yml") ||
				strings.Contains(lower, ".gradle") || strings.Contains(lower, ".properties") ||
				strings.Contains(lower, ".kt") || strings.Contains(lower, ".swift") ||
				strings.Contains(lower, "int.") ||
				strings.Contains(lower, "double.") || strings.Contains(lower, "string.") ||
				strings.Contains(lower, "bool.") || strings.Contains(lower, "list.") ||
				strings.Contains(lower, "map.") || strings.Contains(lower, "set.") ||
				strings.Contains(lower, "object.") || strings.Contains(lower, "iterable.") ||
				strings.Contains(lower, "future.") || strings.Contains(lower, "stream.") ||
				strings.Contains(lower, "duration.") || strings.Contains(lower, "datetime.") ||
				strings.Contains(lower, "num.") || strings.Contains(lower, "regexp.") ||
				strings.Contains(lower, "symbol.") || strings.Contains(lower, "enum.") ||
				strings.Contains(lower, "type.") || strings.Contains(lower, "dynamic.") ||
				strings.Contains(lower, "void.") || strings.Contains(lower, "null.") {
				continue
			}
			key := "domain:" + m
			if !seen[key] {
				seen[key] = true
				findings = append(findings, NetworkEndpointFinding{
					Type:  "domain",
					Value: m,
					Func:  sr.Func,
				})
			}
		}
	}
	return findings
}

// DeobfuscationFinding is a string deobfuscation detection finding.
type DeobfuscationFinding struct {
	Type       string `json:"type"` // "base64", "xor_pattern", "rc4_pattern"
	Value      string `json:"value"`
	Func       string `json:"func,omitempty"`
	Decoded    string `json:"decoded,omitempty"`
	Confidence string `json:"confidence"` // "high", "medium", "low"
}

var (
	base64Re = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+/]{15,}={0,2}$`)
)

// DetectObfuscatedStrings scans string refs for potential obfuscated strings.
func DetectObfuscatedStrings(stringRefs []StringRefRecord) []DeobfuscationFinding {
	var findings []DeobfuscationFinding
	for _, sr := range stringRefs {
		if sr.Value == "" || len(sr.Value) < 8 {
			continue
		}
		// Base64 pattern: long alphanumeric string ending with = or ==
		if base64Re.MatchString(sr.Value) && len(sr.Value) >= 16 {
			// Try to decode as base64
			decoded := tryBase64Decode(sr.Value)
			confidence := "medium"
			if decoded != "" {
				confidence = "high"
			}
			findings = append(findings, DeobfuscationFinding{
				Type:       "base64",
				Value:      sr.Value,
				Func:       sr.Func,
				Decoded:    decoded,
				Confidence: confidence,
			})
			continue
		}
		// XOR pattern: string with high proportion of non-printable chars
		// but with some printable structure (suggests XOR with a key)
		printable := 0
		nonPrintable := 0
		// Iterate BYTES (not runes): len(sr.Value) is a byte count, so the
		// printable/nonPrintable counts must also be per-byte to stay
		// consistent with the len-based threshold below.
		for i := 0; i < len(sr.Value); i++ {
			c := sr.Value[i]
			if c >= 32 && c <= 126 {
				printable++
			} else {
				nonPrintable++
			}
		}
		if nonPrintable > 0 && len(sr.Value) > 10 && printable > len(sr.Value)/2 {
			findings = append(findings, DeobfuscationFinding{
				Type:       "xor_pattern",
				Value:      sr.Value,
				Func:       sr.Func,
				Confidence: "low",
			})
		}
	}
	return findings
}

// tryBase64Decode attempts to decode a base64 string and returns the decoded
// value if it's printable, empty string otherwise.
func tryBase64Decode(s string) string {
	// Add padding if needed
	for len(s)%4 != 0 {
		s += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	// Check if decoded is mostly printable
	printable := 0
	for _, b := range decoded {
		if b >= 32 && b <= 126 || b == 10 || b == 13 {
			printable++
		}
	}
	if printable > len(decoded)*8/10 {
		return string(decoded)
	}
	return ""
}

// StringRefRecord is a minimal string ref record for signal analysis.
// Matches disasm.StringRefRecord but avoids importing disasm package.
type StringRefRecord struct {
	Func    string `json:"func"`
	PC      string `json:"pc"`
	Kind    string `json:"kind"`
	PoolIdx int    `json:"pool_idx"`
	Value   string `json:"value"`
}

// WriteCryptoFindings writes crypto findings to crypto_findings.jsonl.
func WriteCryptoFindings(outDir string, findings []CryptoFinding) error {
	if len(findings) == 0 {
		return nil
	}
	return writeJSONLFile(filepath.Join(outDir, "crypto_findings.jsonl"), findings)
}

// WriteSignalExpansionJSONL writes all signal expansion findings to JSONL files.
// Crypto findings are written separately by WriteCryptoFindings (called from
// pipeline with binary scan results).
func WriteSignalExpansionJSONL(outDir string, stringRefs []StringRefRecord) error {
	// 1. Method Channel enumeration
	mcFindings := EnumerateMethodChannels(stringRefs)
	if len(mcFindings) > 0 {
		if err := writeJSONLFile(filepath.Join(outDir, "method_channels.jsonl"), mcFindings); err != nil {
			return fmt.Errorf("write method_channels.jsonl: %w", err)
		}
	}

	// 3. Plugin enumeration
	pluginFindings := EnumeratePlugins(stringRefs)
	if len(pluginFindings) > 0 {
		if err := writeJSONLFile(filepath.Join(outDir, "plugins.jsonl"), pluginFindings); err != nil {
			return fmt.Errorf("write plugins.jsonl: %w", err)
		}
	}

	// 4. String deobfuscation
	deobFindings := DetectObfuscatedStrings(stringRefs)
	if len(deobFindings) > 0 {
		if err := writeJSONLFile(filepath.Join(outDir, "deobfuscation.jsonl"), deobFindings); err != nil {
			return fmt.Errorf("write deobfuscation.jsonl: %w", err)
		}
	}

	// 5. Network endpoint extraction
	netFindings := ExtractNetworkEndpoints(stringRefs)
	if len(netFindings) > 0 {
		if err := writeJSONLFile(filepath.Join(outDir, "network_endpoints.jsonl"), netFindings); err != nil {
			return fmt.Errorf("write network_endpoints.jsonl: %w", err)
		}
	}

	return nil
}

func writeJSONLFile(path string, entries interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)

	switch v := entries.(type) {
	case []CryptoFinding:
		for _, e := range v {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	case []MethodChannelFinding:
		for _, e := range v {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	case []PluginFinding:
		for _, e := range v {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	case []DeobfuscationFinding:
		for _, e := range v {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	case []NetworkEndpointFinding:
		for _, e := range v {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	case []YaraFinding:
		for _, e := range v {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	case []TaintFinding:
		for _, e := range v {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	case []BehavioralFinding:
		for _, e := range v {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	case []EntropyFinding:
		for _, e := range v {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	}
	return nil
}
