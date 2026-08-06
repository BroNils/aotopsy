// Package signal classifies string references and call-graph context
// into a behavioral report (crypto/network/obfuscation-adjacent
// patterns), generic pattern matching not tied to any specific app.
package signal

import (
	"math"
	"regexp"
	"strings"
)

// Categories for string signal classification.
const (
	CatURL        = "url"
	CatHost       = "host"
	CatEncryption = "encryption"
	CatAuth       = "auth"
	CatNet        = "net"
	CatFileExt    = "file"
	CatBase64Key  = "base64"

	// Suspicious mobile behavior categories.
	CatSIM         = "sim"         // SIM card, IMEI, carrier, MCC/MNC
	CatSMS         = "sms"         // SMS read/send
	CatContacts    = "contacts"    // Contact list access
	CatLocation    = "location"    // GPS, geolocation, geofence
	CatDeviceInfo  = "device"      // Device ID, fingerprinting
	CatCloaking    = "cloaking"    // Keyword/locale gating, redirect tricks
	CatDataCollect = "data"        // Bulk data harvesting
	CatCamera      = "camera"      // Camera access
	CatWebView     = "webview"     // WebView loadUrl, evaluateJavascript, JS bridge
	CatBlockchain  = "blockchain"  // Wallet, mnemonic, seed phrase, blockchain, NFT
	CatGambling    = "gambling"    // Betting, casino, slots, lottery, poker
	CatAttribution = "attribution" // Install referrer, campaign, organic, SDK tracking
)

var (
	reURL       = regexp.MustCompile(`(?i)(https?|wss?|ftp)://`)
	reIPLiteral = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reBase64    = regexp.MustCompile(`^[A-Za-z0-9+/=]{16,}$`)

	// Crypto keywords that are safe for substring matching (long enough, no false positives).
	cryptoKeywords = []string{
		"encrypt", "decrypt", "cipher", "ciphertext",
		"xxtea", "xorcipher", "xordecrypt", "xorencrypt", "xorkey",
		"pbkdf", "argon2", "bcrypt", "scrypt",
		"signature", "digest",
		"hmacsha", "chacha", "blowfish", "twofish",
		"nonce", "saltvalue",
	}

	// Short crypto words need word-boundary matching to avoid false positives
	// ("rsa" in "Traversal", "tea" in "instead", "md5" in random strings).
	reCryptoShort = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(aes|rsa|ecdsa|ecdh|hmac|sha1|sha256|sha512|md5|cbc|ecb|gcm|pkcs|xor|rc4|3des|salt|iv)([^a-zA-Z]|$)`)

	// Auth patterns use word boundaries to avoid camelCase false positives
	// like "brieflyShowPassword" (Flutter UI setting).
	reAuth = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(oauth|jwt|bearer|credential|passwd|apikey|api_key|api-key|authorization|authenticate)([^a-zA-Z]|$)`)

	// These require standalone match (not embedded in camelCase).
	reAuthStandalone = regexp.MustCompile(`(?i)(^|[^a-z])(password|token|secret|login)([^a-z]|$)`)

	netKeywords = []string{
		"socket", "connect", "dns", "proxy", "redirect",
	}

	httpMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

	signalExtensions = []string{
		".dex", ".so", ".apk", ".aab", ".ipa",
		".zip", ".tar", ".gz",
		".json", ".xml", ".yaml", ".yml",
		".db", ".sqlite",
		".key", ".pem", ".cert", ".crt", ".p12", ".jks",
		".js", ".lua", ".py",
	}

	// SIM / telephony patterns.
	// Use case-sensitive camelCase-aware matching via classifyContains.
	// All keyword lists use normalized form: lowercase, no separators.
	// normalizeForMatch strips _, -, space, . before matching.

	simKeywords = []string{
		"simcard", "checksim", "imei", "imsi",
		"telephon", "subscriberid", "getline1", "simoperator",
		"simcountry", "simserial",
	}

	smsKeywords = []string{
		"smslog", "sendsms", "readsms", "smsmanager",
	}
	// "sms" alone is too short for containsKeyword (matches inside other words).
	// Handled via regex below.
	reSMS = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(sms|mms)([^a-zA-Z]|$)`)

	contactKeywords = []string{
		"contactlist", "addressbook", "calllog", "readcontacts",
		"contactaddress", "phonenumber",
	}

	locationKeywords = []string{
		"geolocation", "geofence", "latitude", "longitude",
		"currentlocation", "locationservice", "requestlocation",
		"enablelocation", "locationexception", "locationpermission",
		"lastknownlocation", "fusedlocation", "geopoint",
		"locationcallback", "locationlistener", "locationmanager",
		"locationrequest", "isenablelocation",
	}
	// "gps" needs word-boundary matching (would match inside longer words).
	reLocationShort = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(gps)([^a-zA-Z]|$)`)

	deviceInfoKeywords = []string{
		"deviceid", "androidid", "getdevice", "deviceinfo",
		"devicefingerprint", "devicemodel", "deviceattributes",
		"installreferrer", "installerstore",
		"packageinfo", "getpackageinfo", "packagename",
		"getinstalledpackages", "packagemanager",
		"applicationinfo", "getapplicationinfo",
	}

	cloakingKeywords = []string{
		"checkkeyword", "keywordcheck", "keywordmismatch",
		"isallowed", "checkandlaunch", "checkredirect",
		"cloak", "appcountry",
		// Locale / timezone / timing checks
		"checklanguage", "checklocale", "checktimezone",
		"getdefaultlocale", "systemlocale", "devicelanguage",
		"timedelay", "scheduletask", "setinterval",
	}

	reDataCollect = regexp.MustCompile(`(?i)(data.?collect|mobile.?data|send.?all.?mobile|collect.?data|harvest|bulk.?data|scrape|exfiltrat)`)

	cameraKeywords = []string{
		"camerapermission", "cameraopen", "getavailablecameras",
		"takepicture", "recordvideo",
	}

	walletKeywords = []string{
		// Mnemonic / seed phrase
		"mnemonic", "seedphrase", "bip39", "bip44", "bip32",
		"recoveryphrase", "backupphrase", "secretphrase",
		"wordlist", "passphrase", "derivepath",
		// Wallet core
		"privatek", "publickey", "keystore", "keychain",
		"hdwallet", "coldwallet", "hotwallet",
		"walletconnect", "walletaddress", "walletbalance",
		"walletprovider", "walletadapter",
		// Chains & tokens (long enough for substring match)
		"blockchain", "smartcontract",
		"ethereum", "solana", "bitcoin", "binance", "polygon",
		"tether", "usdc", "usdt",
		"erc20", "bep20", "trc20",
		// Wallets / services
		"metamask", "trustwallet", "phantom", "coinbase",
		"uniswap", "pancakeswap", "opensea",
		// Web3 (long enough for substring match)
		"gasprice", "gaslimit", "gasfee",
		// NFT
		"nftmint", "nftmarket", "tokenuri", "tokenmeta",
	}
	reWallet = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(wallet|mnemonic|seed.?phrase|private.?key|web3|dapp|nft|defi|swap|stake|airdrop|bitcoin|ether|crypto.?currency|token.?transfer)([^a-zA-Z]|$)`)

	gamblingKeywords = []string{
		// Casino / slots
		"casino", "slotmachine", "roulette", "blackjack",
		"jackpot", "spinwheel", "freespin",
		// Betting / wager
		"sportsbet", "placebet", "betslip", "oddscalc",
		"bookmaker", "bookie", "handicap",
		// Lottery
		"lottery", "lotto", "lucknumber", "drawresult",
		// Poker / card games
		"pokerroom", "pokertable", "texasholdem",
		// Money flow
		"placewager", "payout", "cashout",
		"topup", "recharge",
	}
	reGambling = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(bet|wager|casino|slot|gamble|lottery|lotto|poker|roulette|jackpot|withdraw|deposit|reward|bonus|payout|cashout|spin)([^a-zA-Z]|$)`)

	attributionKeywords = []string{
		// Install attribution
		"installreferrer", "installattribution", "installsource",
		"googleplayinstallreferrer",
		// Campaign / conversion tracking
		"campaigndata", "campaignattribution", "campaigntracking",
		"conversiondata", "conversionvalue", "conversiontracking",
		"deferreddeeplink",
		// Attribution SDK names (long enough for substring match)
		"appsflyerlib", "appsflyerdata", "appsflyerconv",
		"branchmetrics", "branchuniversalobj",
		"kochavatracker", "kochavaevent",
		"singularsdk", "tenjinsdk", "airbridgesdk",
		"adjustattribution", "adjustsession", "adjustevent", "adjustconfig",
		"adjustdevice", "getadid",
	}
	reAttribution = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(referrer|organic|campaign|attribution|appsflyer|kochava|utm_source|utm_medium|utm_campaign|utm_content|utm_term|install_referrer|ad_id|adid|gclid|fbclid)([^a-zA-Z]|$)`)

	webviewKeywords = []string{
		// WebView core
		"loadurl", "loaddata", "loadrequest",
		"evaluatejavascript", "addjavascriptinterface",
		"javascriptchannel", "webviewclient", "webviewcontroller",
		"webchromeclient", "inappwebview", "inappbrowser",
		"shouldoverrideurlloading", "shouldinterceptrequest",
		"webmessagelistener", "onpagestarted", "onpagefinished",
		// Chrome / custom tabs
		"customtab", "opencustomtab", "chrometab", "chromeclient",
		// Intent / deep linking
		"startactivity", "intentfilter", "deeplink", "applink",
		"launchurl", "canlaunch", "urlscheme",
		// Java bridge / JNI
		"javabridge", "jsbridge", "nativebridge",
		"javascriptinterface", "postmessage",
		// Cookies
		"cookiemanager", "setcookie", "getcookie", "clearcookie",
		"cookiejar", "cookiestore",
	}
	reWebView = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(webview|loadurl|cookie|intent|jsbridge)([^a-zA-Z]|$)`)
)

// ClassifyString returns the set of signal categories matching the value.
// Returns nil if the string carries no signal.
func ClassifyString(value string) []string {
	if len(value) < 2 {
		return nil
	}

	var cats []string
	lower := strings.ToLower(value)

	// URL
	if reURL.MatchString(value) {
		cats = append(cats, CatURL)
	}

	// Host (IP literal)
	if reIPLiteral.MatchString(value) {
		cats = append(cats, CatHost)
	}

	// Crypto: keyword substring match + word-boundary regex for short words.
	if containsKeyword(value, cryptoKeywords) || reCryptoShort.MatchString(value) {
		cats = append(cats, CatEncryption)
	}

	// Auth (word-boundary matching to avoid camelCase false positives).
	if reAuth.MatchString(value) || reAuthStandalone.MatchString(value) {
		cats = append(cats, CatAuth)
	}

	// Net (HTTP methods or network keywords)
	for _, m := range httpMethods {
		if value == m {
			cats = append(cats, CatNet)
			break
		}
	}
	if !containsCat(cats, CatNet) {
		for _, w := range netKeywords {
			if strings.Contains(lower, w) {
				cats = append(cats, CatNet)
				break
			}
		}
	}

	// File extension
	for _, ext := range signalExtensions {
		if strings.HasSuffix(lower, ext) || strings.Contains(lower, ext+" ") || strings.Contains(lower, ext+",") {
			cats = append(cats, CatFileExt)
			break
		}
	}

	// Base64/hex key (high-entropy, standalone).
	// Exclude camelCase identifiers which match the character set but aren't keys.
	trimmed := strings.TrimSpace(value)
	if reBase64.MatchString(trimmed) && entropy(value) > 3.5 && !isCamelCase(trimmed) {
		cats = append(cats, CatBase64Key)
	}

	// SIM / telephony
	if containsKeyword(value, simKeywords) {
		cats = append(cats, CatSIM)
	}

	// SMS
	if containsKeyword(value, smsKeywords) || reSMS.MatchString(value) {
		cats = append(cats, CatSMS)
	}

	// Contacts
	if containsKeyword(value, contactKeywords) {
		cats = append(cats, CatContacts)
	}

	// Location / GPS
	if containsKeyword(value, locationKeywords) || reLocationShort.MatchString(value) {
		cats = append(cats, CatLocation)
	}

	// Device info / fingerprinting
	if containsKeyword(value, deviceInfoKeywords) {
		cats = append(cats, CatDeviceInfo)
	}

	// Cloaking
	if containsKeyword(value, cloakingKeywords) {
		cats = append(cats, CatCloaking)
	}

	// Data collection
	if reDataCollect.MatchString(value) {
		cats = append(cats, CatDataCollect)
	}

	// Camera
	if containsKeyword(value, cameraKeywords) {
		cats = append(cats, CatCamera)
	}

	// WebView
	if containsKeyword(value, webviewKeywords) || reWebView.MatchString(value) {
		cats = append(cats, CatWebView)
	}

	// Crypto wallet / blockchain
	if containsKeyword(value, walletKeywords) || reWallet.MatchString(value) {
		cats = append(cats, CatBlockchain)
	}

	// Gambling
	if containsKeyword(value, gamblingKeywords) || reGambling.MatchString(value) {
		cats = append(cats, CatGambling)
	}

	// Attribution / install tracking
	if containsKeyword(value, attributionKeywords) || reAttribution.MatchString(value) {
		cats = append(cats, CatAttribution)
	}

	return cats
}

// IsMundaneTHR returns true for THR field names that represent allocations,
// write barriers, or type checks — noise in the signal graph.
func IsMundaneTHR(name string) bool {
	lower := strings.ToLower(name)
	mundanePatterns := []string{
		"allocate",
		"write_barrier",
		"store_buffer",
		"type_test",
		"subtype_check",
		"call_to_runtime_ep",
		"stack_overflow",
		"null_error",
		"range_error",
		"error_", // covers null_error, range_error, write_error, etc.
		"deoptimize",
		"megamorphic_call",
		"switchable_call",
		"monomorphic_",
		"lazy_deopt",
		"safepoint",
	}
	for _, p := range mundanePatterns {
		if strings.Contains(lower, p) {
			// Exception: call_native_through_safepoint_ep is interesting (FFI/JNI).
			if strings.Contains(lower, "native") {
				return false
			}
			return true
		}
	}
	return false
}

// Severity levels for signal categories.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
)

// CategorySeverity returns the severity level for a category.
func CategorySeverity(cat string) string {
	switch cat {
	case CatEncryption, CatAuth, CatSIM, CatSMS, CatContacts, CatCloaking, CatDataCollect, CatWebView, CatBlockchain, CatGambling:
		return SeverityHigh
	case CatURL, CatHost, CatBase64Key, CatLocation, CatDeviceInfo, CatCamera, CatAttribution:
		return SeverityMedium
	case CatNet, CatFileExt, "thr":
		return SeverityLow
	default:
		return SeverityLow
	}
}

// MaxSeverity returns the highest severity from a list of categories.
func MaxSeverity(categories []string) string {
	best := ""
	for _, c := range categories {
		s := CategorySeverity(c)
		if s == SeverityHigh {
			return SeverityHigh
		}
		if s == SeverityMedium {
			best = SeverityMedium
		} else if best == "" {
			best = SeverityLow
		}
	}
	if best == "" {
		return SeverityLow
	}
	return best
}

// isCamelCase returns true if the string looks like a camelCase/PascalCase identifier.
// It checks for lowercase-to-uppercase transitions (e.g. "checkSimCard").
func isCamelCase(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= 'a' && s[i-1] <= 'z' && s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// normalizeForMatch strips underscores, hyphens, spaces, and dots from a
// lowercased string. This lets "checkSimCard", "check_sim_card", and
// "check sim card" all match the keyword "checksimcard".
func normalizeForMatch(s string) string {
	lower := strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(lower))
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c != '_' && c != '-' && c != ' ' && c != '.' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// containsKeyword checks if the normalized value contains any keyword.
// Keywords should be lowercase with no separators (e.g. "checksimcard").
func containsKeyword(value string, keywords []string) bool {
	norm := normalizeForMatch(value)
	for _, kw := range keywords {
		if strings.Contains(norm, kw) {
			return true
		}
	}
	return false
}

func containsCat(cats []string, cat string) bool {
	for _, c := range cats {
		if c == cat {
			return true
		}
	}
	return false
}

// entropy computes Shannon entropy of a string in bits per character.
func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var ent float64
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}
