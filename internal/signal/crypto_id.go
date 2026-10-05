package signal

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	// net/netip, not net: importing "net" pulls in runtime/cgo, which turns the
	// binary into a dynamically linked cgo executable whose glibc per-thread malloc
	// arenas reserve ~1 GB of address space and break the repository's
	// `ulimit -v 2500000` budget (see TestCommandDoesNotLinkNetOrCgo).
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"aotopsy/internal/elfx"
	"aotopsy/internal/jsonutil"
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
	Algorithm string `json:"algorithm"`
	Constant  string `json:"constant"`
	PoolIndex int    `json:"pool_index"`
	Value     string `json:"value"`
}

type cryptoPattern struct {
	algo  string
	hex   string
	value uint64
	width int
	bytes []byte
}

func cryptoPatterns() []cryptoPattern {
	keys := make([]string, 0, len(cryptoAlgorithmID))
	for hex := range cryptoAlgorithmID {
		keys = append(keys, hex)
	}
	sort.Strings(keys)
	patterns := make([]cryptoPattern, 0, len(keys))
	for _, hex := range keys {
		if !isDistinctiveConstant(hex) {
			continue
		}
		var val uint64
		if _, err := fmt.Sscanf(hex, "0x%x", &val); err != nil {
			continue
		}
		width := 4
		if len(strings.TrimPrefix(hex, "0x")) > 8 {
			width = 8
		}
		buf := make([]byte, width)
		if width == 4 {
			binary.LittleEndian.PutUint32(buf, uint32(val))
		} else {
			binary.LittleEndian.PutUint64(buf, val)
		}
		patterns = append(patterns, cryptoPattern{
			algo: cryptoAlgorithmID[hex], hex: hex, value: val, width: width, bytes: buf,
		})
	}
	return patterns
}

type cryptoAccumulator struct {
	seen       map[string]bool
	familyHits map[string]int
	findings   []CryptoFinding
}

func newCryptoAccumulator() *cryptoAccumulator {
	return &cryptoAccumulator{seen: map[string]bool{}, familyHits: map[string]int{}}
}

func (a *cryptoAccumulator) add(p cryptoPattern, absoluteOffset int) {
	key := p.algo + ":" + p.hex
	if a.seen[key] {
		return
	}
	a.seen[key] = true
	a.familyHits[algorithmFamily(p.algo)]++
	a.findings = append(a.findings, CryptoFinding{
		Algorithm: p.algo,
		Constant:  p.hex,
		PoolIndex: -1,
		Value:     fmt.Sprintf("binary_offset=0x%x", absoluteOffset),
	})
}

func (a *cryptoAccumulator) finish() []CryptoFinding {
	kept := a.findings[:0]
	for _, f := range a.findings {
		if isPrintableASCIIConstant(f.Constant) && a.familyHits[algorithmFamily(f.Algorithm)] < 2 {
			continue
		}
		kept = append(kept, f)
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].Algorithm != kept[j].Algorithm {
			return kept[i].Algorithm < kept[j].Algorithm
		}
		return kept[i].Constant < kept[j].Constant
	})
	return kept
}

// IdentifyCryptoFromPoolImmediates reads pool_immediates.jsonl and identifies
// crypto algorithm constants. Returns a list of findings.
func IdentifyCryptoFromPoolImmediates(inDir string) ([]CryptoFinding, error) {
	path := filepath.Join(inDir, "pool_immediates.jsonl")
	records, err := jsonutil.ReadJSONL[PoolImmediateRecord](path, jsonutil.StandardLimits)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // optional artifact
		}
		return nil, fmt.Errorf("read pool immediates: %w", err)
	}

	type candidate struct {
		finding   CryptoFinding
		family    string
		printable bool
	}
	var candidates []candidate
	familyConstants := map[string]map[string]bool{}
	for _, rec := range records {
		hex := strings.ToLower(rec.Hex)
		algo, ok := cryptoAlgorithmID[hex]
		if !ok || !isDistinctiveConstant(hex) {
			continue
		}
		family := algorithmFamily(algo)
		if familyConstants[family] == nil {
			familyConstants[family] = map[string]bool{}
		}
		familyConstants[family][hex] = true
		candidates = append(candidates, candidate{
			finding: CryptoFinding{
				Algorithm: algo,
				Constant:  hex,
				PoolIndex: rec.Index,
				Value:     rec.Hex,
			},
			family:    family,
			printable: isPrintableASCIIConstant(hex),
		})
	}
	findings := make([]CryptoFinding, 0, len(candidates))
	for _, c := range candidates {
		// Printable constants such as ChaCha20's "expa" are ordinary text in
		// isolation. Require a second distinct constant from the same family,
		// matching the executable-section scanner's corroboration rule.
		if c.printable && len(familyConstants[c.family]) < 2 {
			continue
		}
		findings = append(findings, c.finding)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Algorithm != findings[j].Algorithm {
			return findings[i].Algorithm < findings[j].Algorithm
		}
		if findings[i].Constant != findings[j].Constant {
			return findings[i].Constant < findings[j].Constant
		}
		return findings[i].PoolIndex < findings[j].PoolIndex
	})
	return findings, nil
}

// isDistinctiveConstant reports whether a constant's raw bytes are unusual
// enough that finding them in a binary is evidence of anything.
//
// A constant qualifies when at least three of its bytes are non-zero, no byte
// value repeats more than twice, and it is not a power of two. That rejects
// the AES Rcon table (0x01000000, 0x02000000 … 0x80000000) and Keccak
// RC[0]/RC[1] while keeping SHA/MD5/CRC/ChaCha/BLAKE constants.
func isDistinctiveConstant(hex string) bool {
	var val uint64
	if _, err := fmt.Sscanf(hex, "0x%x", &val); err != nil {
		return false
	}
	width := 4
	if len(strings.TrimPrefix(hex, "0x")) > 8 {
		width = 8
	}
	var counts [256]int
	nonZero := 0
	for i := 0; i < width; i++ {
		b := byte(val >> (8 * uint(i)))
		counts[b]++
		if b != 0 {
			nonZero++
		}
	}
	if nonZero < 3 {
		return false
	}
	for _, c := range counts {
		if c > 2 {
			return false
		}
	}
	if val != 0 && val&(val-1) == 0 {
		return false // power of two
	}
	return true
}

// IdentifyCryptoFromELF identifies constants in executable code from the same
// already-validated ELF descriptor used by the rest of the pipeline. x86_64 can
// carry a complete immediate byte sequence in an instruction, but AArch64
// LoadImmediate materialises values as MOVZ/MOVN followed by MOVK chunks. A raw
// little-endian byte search therefore systematically misses AArch64 constants
// and can match unrelated data. Production scanning is restricted to validated
// executable sections; unit tests exercise the pure byte scanner directly.
func IdentifyCryptoFromELF(ef *elfx.File) ([]CryptoFinding, error) {
	if ef == nil {
		return nil, fmt.Errorf("crypto scan: nil ELF source")
	}
	patterns := cryptoPatterns()
	acc := newCryptoAccumulator()
	sections, err := ef.ExecutableSections(256 << 20)
	if err != nil {
		return nil, fmt.Errorf("crypto scan executable sections: %w", err)
	}
	maxInt := uint64(^uint(0) >> 1)
	for _, sec := range sections {
		if sec.Offset > maxInt {
			return nil, fmt.Errorf("ELF executable section %q offset is not addressable", sec.Name)
		}
		start := int(sec.Offset)
		if ef.IsARM64() {
			identifyCryptoFromARM64Code(sec.Data, start, patterns, acc)
		} else {
			identifyCryptoFromRawBytes(sec.Data, start, patterns, acc)
		}
	}
	return acc.finish(), nil
}

func identifyCryptoFromRawBytes(data []byte, baseOffset int, patterns []cryptoPattern, acc *cryptoAccumulator) {
	for _, pat := range patterns {
		offset := 0
		for offset <= len(data)-len(pat.bytes) {
			idx := bytes.Index(data[offset:], pat.bytes)
			if idx < 0 {
				break
			}
			abs := offset + idx
			acc.add(pat, baseOffset+abs)
			offset = abs + len(pat.bytes)
		}
	}
}

type moveWideKind uint8

const (
	moveWideN moveWideKind = iota + 1
	moveWideZ
	moveWideK
)

// decodeMoveWide decodes AArch64 MOVN/MOVZ/MOVK (32- and 64-bit). These are
// the instructions used by Dart's Assembler::LoadImmediate to materialise
// integer constants that are not pool-loaded.
func decodeMoveWide(raw uint32) (kind moveWideKind, rd int, imm uint64, shift uint, width int, ok bool) {
	top := raw & 0x7F800000 // ignore sf (bit 31)
	switch top {
	case 0x12800000:
		kind = moveWideN
	case 0x52800000:
		kind = moveWideZ
	case 0x72800000:
		kind = moveWideK
	default:
		return 0, 0, 0, 0, 0, false
	}
	width = 32
	if raw&(1<<31) != 0 {
		width = 64
	}
	hw := uint((raw >> 21) & 0x3)
	if width == 32 && hw >= 2 {
		return 0, 0, 0, 0, 0, false
	}
	return kind, int(raw & 0x1F), uint64((raw >> 5) & 0xFFFF), hw * 16, width, true
}

func identifyCryptoFromARM64Code(code []byte, baseOffset int, patterns []cryptoPattern, acc *cryptoAccumulator) {
	byValue := make(map[uint64][]cryptoPattern)
	for _, p := range patterns {
		byValue[p.value] = append(byValue[p.value], p)
	}
	for off := 0; off+4 <= len(code); off += 4 {
		raw := binary.LittleEndian.Uint32(code[off : off+4])
		kind, rd, imm, shift, width, ok := decodeMoveWide(raw)
		if !ok || kind == moveWideK {
			continue
		}
		mask := uint64(^uint32(0))
		if width == 64 {
			mask = ^uint64(0)
		}
		value := (imm << shift) & mask
		if kind == moveWideN {
			value = (^value) & mask
		}
		end := off + 4
		for end+4 <= len(code) {
			next := binary.LittleEndian.Uint32(code[end : end+4])
			nextKind, nextRD, nextImm, nextShift, nextWidth, nextOK := decodeMoveWide(next)
			if !nextOK || nextKind != moveWideK || nextRD != rd || nextWidth != width {
				break
			}
			chunkMask := uint64(0xFFFF) << nextShift
			value = (value &^ chunkMask) | ((nextImm << nextShift) & chunkMask)
			value &= mask
			end += 4
		}
		for _, p := range byValue[value] {
			if p.width*8 == width {
				acc.add(p, baseOffset+off)
			}
		}
	}
}

// algorithmFamily is the cipher name in an entry like "ChaCha20 'expa'"
// or "SHA-256 K[0]" -- everything before the first space.
func algorithmFamily(algo string) string {
	if i := strings.IndexByte(algo, ' '); i >= 0 {
		return algo[:i]
	}
	return algo
}

// isPrintableASCIIConstant reports whether every byte of the constant is
// printable ASCII, i.e. whether finding it in a binary is as likely to be
// text as it is to be a cipher constant.
func isPrintableASCIIConstant(hex string) bool {
	var val uint64
	if _, err := fmt.Sscanf(hex, "0x%x", &val); err != nil {
		return false
	}
	width := 4
	if len(strings.TrimPrefix(hex, "0x")) > 8 {
		width = 8
	}
	for i := 0; i < width; i++ {
		b := byte(val >> (8 * uint(i)))
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// MethodChannelFinding is a Flutter MethodChannel enumeration finding.
type MethodChannelFinding struct {
	Channel    string   `json:"channel"`
	Functions  []string `json:"functions,omitempty"`
	Confidence string   `json:"confidence"`
}

var methodChannelRe = regexp.MustCompile(`MethodChannel\s*\(\s*["']([^"']+)["']\s*\)`)

// EnumerateMethodChannels scans string refs for MethodChannel("name") patterns
// and also detects Flutter platform channel names by pattern matching.
func EnumerateMethodChannels(stringRefs []StringRefRecord) []MethodChannelFinding {
	funcsByChannel := map[string]map[string]bool{}
	confidenceByChannel := map[string]string{}
	add := func(channel, fn, confidence string) {
		if channel == "" {
			return
		}
		if funcsByChannel[channel] == nil {
			funcsByChannel[channel] = map[string]bool{}
		}
		if fn != "" {
			funcsByChannel[channel][fn] = true
		}
		if confidenceRank(confidence) > confidenceRank(confidenceByChannel[channel]) {
			confidenceByChannel[channel] = confidence
		}
	}
	for _, sr := range stringRefs {
		if sr.Value == "" {
			continue
		}
		// Pattern 1: MethodChannel("name") — Dart source pattern
		matches := methodChannelRe.FindStringSubmatch(sr.Value)
		if len(matches) >= 2 {
			add(matches[1], sr.Func, "medium")
			continue
		}
		// Pattern 2: Explicit MethodChannel references
		if strings.Contains(sr.Value, "methodChannel") || strings.Contains(sr.Value, "MethodChannel") {
			if len(sr.Value) > 5 && len(sr.Value) < 200 {
				add(sr.Value, sr.Func, "low")
			}
			continue
		}
		// Pattern 3: Flutter platform channel naming convention
		// Channels like "dev.flutter/channel-buffers", "flutter/platform", etc.
		if strings.Contains(sr.Value, "dev.flutter/") ||
			strings.Contains(sr.Value, "flutter/platform") ||
			strings.Contains(sr.Value, "flutter/navigation") ||
			strings.Contains(sr.Value, "flutter/textinput") ||
			strings.Contains(sr.Value, "flutter/keyevent") ||
			strings.Contains(sr.Value, "flutter/accessibility") ||
			strings.Contains(sr.Value, "flutter/system") ||
			strings.Contains(sr.Value, "flutter/localization") ||
			strings.Contains(sr.Value, "flutter/sensors") ||
			strings.Contains(sr.Value, "flutter/settings") ||
			strings.Contains(sr.Value, "flutter/lifecycle") {
			add(sr.Value, sr.Func, "medium")
		}
		// Pattern 4: BinaryMessenger / platform channel infrastructure
		if strings.Contains(sr.Value, "BinaryMessenger") ||
			strings.Contains(sr.Value, "PlatformChannel") ||
			strings.Contains(sr.Value, "BasicMessageChannel") {
			add(sr.Value, sr.Func, "low")
		}
	}
	findings := make([]MethodChannelFinding, 0, len(funcsByChannel))
	for channel, set := range funcsByChannel {
		findings = append(findings, MethodChannelFinding{Channel: channel, Functions: sortedSet(set), Confidence: confidenceByChannel[channel]})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Channel < findings[j].Channel })
	return findings
}

// PluginFinding is a Flutter plugin enumeration finding.
type PluginFinding struct {
	Plugin     string   `json:"plugin"`
	Functions  []string `json:"functions,omitempty"`
	Confidence string   `json:"confidence"`
}

// Known Flutter plugin package name patterns.
var pluginPatterns = []string{
	"flutter_plugin_", "_plugin", "plugin_android", "plugin_ios",
	"missingpluginexception", "video_player", "path_provider",
	"shared_preferences", "url_launcher", "image_picker", "file_picker",
	"camera_android", "camera_avfoundation", "camera_web", "geolocator", "permission_handler", "firebase_",
	"google_maps_flutter", "webview_flutter", "local_auth", "connectivity_plus",
	"device_info_plus", "package_info_plus", "flutter_local_notifications",
	"flutter_push", "jpush", "umeng", "tencent_", "aliyun_",
	"bytedance_", "huawei_", "xiaomi_", "pluginregistry", "flutterplugin",
}

// EnumeratePlugins scans string refs for Flutter plugin package names.
func EnumeratePlugins(stringRefs []StringRefRecord) []PluginFinding {
	funcsByPlugin := map[string]map[string]bool{}
	for _, sr := range stringRefs {
		if sr.Value == "" {
			continue
		}
		val := strings.ToLower(sr.Value)
		for _, pat := range pluginPatterns {
			if strings.Contains(val, pat) {
				if funcsByPlugin[sr.Value] == nil {
					funcsByPlugin[sr.Value] = map[string]bool{}
				}
				if sr.Func != "" {
					funcsByPlugin[sr.Value][sr.Func] = true
				}
				break
			}
		}
	}
	findings := make([]PluginFinding, 0, len(funcsByPlugin))
	for plugin, set := range funcsByPlugin {
		findings = append(findings, PluginFinding{Plugin: plugin, Functions: sortedSet(set), Confidence: "low"})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Plugin < findings[j].Plugin })
	return findings
}

// NetworkEndpointFinding is a network endpoint extraction finding.
type NetworkEndpointFinding struct {
	Type       string   `json:"type"` // "url", "ip", "domain"
	Value      string   `json:"value"`
	Functions  []string `json:"functions,omitempty"`
	Confidence string   `json:"confidence"`
}

var (
	urlRe    = regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
	ipRe     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	domainRe = regexp.MustCompile(`\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b`)
)

// fileExtensions are suffixes that mean the match is a file name, not a host.
var fileExtensions = []string{
	".dart", ".go", ".json", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".webp",
	".class", ".java", ".xml", ".so", ".h", ".c", ".cc", ".cpp", ".py", ".js",
	".ts", ".html", ".css", ".md", ".yaml", ".yml", ".gradle", ".properties",
	".kt", ".swift", ".dill", ".jar", ".aar", ".plist", ".pb", ".proto",
}

// dartTypePrefixes are core-library type names; `Iterable.first` and friends
// match the domain regex but are member accesses.
var dartTypePrefixes = []string{
	"int", "double", "string", "bool", "list", "map", "set", "object",
	"iterable", "future", "stream", "duration", "datetime", "num", "regexp",
	"symbol", "enum", "type", "dynamic", "void", "null", "uri", "error",
	"exception", "function", "comparable", "pattern", "match", "runes",
	"stringbuffer", "bigint", "stopwatch", "invocation",
}

// isNotADomain reports whether a domain-regex match should be discarded.
//
// The extension test is a SUFFIX test on purpose. The earlier version used
// strings.Contains for each extension, which meant ".c" matched "google.com",
// ".so" matched "cdn.social" and ".h" matched anything with ".h" in it --
// i.e. essentially every real domain was thrown away, and the file that this
// analysis exists to produce came out empty.
func isNotADomain(m string) bool {
	lower := strings.ToLower(m)
	for _, ext := range fileExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	// `Type.member` — the label before the first dot is a Dart core type.
	head := lower
	if i := strings.Index(head, "."); i >= 0 {
		head = head[:i]
	}
	for _, p := range dartTypePrefixes {
		if head == p {
			return true
		}
	}
	// A real host's last label (the TLD) is alphabetic and at least 2 chars.
	tld := lower
	if i := strings.LastIndex(tld, "."); i >= 0 {
		tld = tld[i+1:]
	}
	if len(tld) < 2 {
		return true
	}
	for i := 0; i < len(tld); i++ {
		if tld[i] < 'a' || tld[i] > 'z' {
			return true
		}
	}
	return false
}

// ExtractNetworkEndpoints scans string refs for URLs, IPs, and domains.
func ExtractNetworkEndpoints(stringRefs []StringRefRecord) []NetworkEndpointFinding {
	type endpointKey struct{ typ, value string }
	funcsByEndpoint := map[endpointKey]map[string]bool{}
	confidenceByEndpoint := map[endpointKey]string{}
	add := func(typ, value, fn, confidence string) {
		key := endpointKey{typ: typ, value: value}
		if funcsByEndpoint[key] == nil {
			funcsByEndpoint[key] = map[string]bool{}
		}
		if fn != "" {
			funcsByEndpoint[key][fn] = true
		}
		if confidenceRank(confidence) > confidenceRank(confidenceByEndpoint[key]) {
			confidenceByEndpoint[key] = confidence
		}
	}
	for _, sr := range stringRefs {
		if sr.Value == "" || len(sr.Value) < 4 {
			continue
		}
		// URLs
		for _, m := range urlRe.FindAllString(sr.Value, -1) {
			m = strings.TrimRight(m, ".,;")
			parsed, err := url.Parse(m)
			if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				continue
			}
			add("url", m, sr.Func, "medium")
		}
		// IPs (skip 0.0.0.0, 127.0.0.1, 255.x)
		for _, m := range ipRe.FindAllString(sr.Value, -1) {
			ip, err := netip.ParseAddr(m)
			if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || strings.HasPrefix(m, "255.") {
				continue
			}
			add("ip", m, sr.Func, "medium")
		}
		// Domains (must have at least one dot, not start with a number)
		for _, m := range domainRe.FindAllString(sr.Value, -1) {
			if len(m) < 5 || m[0] >= '0' && m[0] <= '9' {
				continue
			}
			// Skip common false positives.
			if isNotADomain(m) {
				continue
			}
			add("domain", m, sr.Func, "low")
		}
	}
	findings := make([]NetworkEndpointFinding, 0, len(funcsByEndpoint))
	for key, set := range funcsByEndpoint {
		findings = append(findings, NetworkEndpointFinding{Type: key.typ, Value: key.value, Functions: sortedSet(set), Confidence: confidenceByEndpoint[key]})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Type != findings[j].Type {
			return findings[i].Type < findings[j].Type
		}
		return findings[i].Value < findings[j].Value
	})
	return findings
}

func sortedSet(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func confidenceRank(confidence string) int {
	switch confidence {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
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
	base64Re = regexp.MustCompile(`^[A-Za-z0-9+/]{12,}={0,2}$`)
)

// DetectObfuscatedStrings scans string refs for potential obfuscated strings.
func DetectObfuscatedStrings(stringRefs []StringRefRecord) []DeobfuscationFinding {
	var findings []DeobfuscationFinding
	for _, sr := range stringRefs {
		if sr.Value == "" || len(sr.Value) < 8 {
			continue
		}
		// Base64-shaped text is common in identifiers and random tokens. Only
		// report it when decoding succeeds to mostly printable text; shape alone
		// is not evidence of encoding or obfuscation.
		if base64Re.MatchString(sr.Value) && len(sr.Value) >= 16 {
			decoded := tryBase64Decode(sr.Value)
			if decoded == "" {
				continue
			}
			findings = append(findings, DeobfuscationFinding{
				Type:       "base64",
				Value:      sr.Value,
				Func:       sr.Func,
				Decoded:    decoded,
				Confidence: "medium",
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
	return writeSignalJSONL(filepath.Join(outDir, "crypto_findings.jsonl"), findings)
}

// WriteSignalExpansionJSONL writes all signal expansion findings to JSONL files.
// Crypto findings are written separately by WriteCryptoFindings (called from
// pipeline with binary scan results).
func WriteSignalExpansionJSONL(outDir string, stringRefs []StringRefRecord) error {
	// 1. Method Channel enumeration
	mcFindings := EnumerateMethodChannels(stringRefs)
	if err := writeSignalJSONL(filepath.Join(outDir, "method_channels.jsonl"), mcFindings); err != nil {
		return fmt.Errorf("write method_channels.jsonl: %w", err)
	}

	// 2. Plugin enumeration
	pluginFindings := EnumeratePlugins(stringRefs)
	if err := writeSignalJSONL(filepath.Join(outDir, "plugins.jsonl"), pluginFindings); err != nil {
		return fmt.Errorf("write plugins.jsonl: %w", err)
	}

	// 3. String deobfuscation
	deobFindings := DetectObfuscatedStrings(stringRefs)
	if err := writeSignalJSONL(filepath.Join(outDir, "deobfuscation.jsonl"), deobFindings); err != nil {
		return fmt.Errorf("write deobfuscation.jsonl: %w", err)
	}

	// 4. Network endpoint extraction
	netFindings := ExtractNetworkEndpoints(stringRefs)
	if err := writeSignalJSONL(filepath.Join(outDir, "network_endpoints.jsonl"), netFindings); err != nil {
		return fmt.Errorf("write network_endpoints.jsonl: %w", err)
	}

	return nil
}

func writeSignalJSONL[T any](path string, entries []T) error {
	_, err := jsonutil.WriteJSONLFile(path, entries)
	return err
}
