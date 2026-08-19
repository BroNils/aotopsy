// Package signal classifies string references and call-graph context
// into a behavioral report (crypto/network/obfuscation-adjacent
// patterns), generic pattern matching not tied to any specific app.
package signal

import (
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

	// Security analysis categories (gap-analysis §4.1).
	CatRooting       = "rooting"        // Root/jailbreak: magisk, supersu, xposed, frida-server
	CatAntiAnalysis  = "anti_analysis"  // Anti-debug, anti-VM, anti-frida, emulator detection
	CatSSLPinning    = "ssl_pinning"    // Certificate pinning, X509TrustManager
	CatAccessibility = "accessibility"  // AccessibilityService, keylogger, screenCapture
	CatFraud         = "fraud"          // Phishing, OTP, banking, card numbers
	CatDynamicLoad   = "dynamic_load"   // DynamicLibrary.open, loadLibrary, mirrorSystem
	CatIPC           = "ipc"            // Binder, ServiceManager, AIDL, ContentProvider
	CatCovertChannel = "covert_channel" // Tor, socks5, proxychain, DNS tunnel
	CatDRMBypass     = "drm_bypass"     // Widevine, FairPlay, PlayReady
	CatObfuscation   = "obfuscation"    // Short meaningless names, identifier entropy
	CatCryptoConst   = "crypto_const"   // AES S-box, SHA-256 K, crypto magic numbers
	CatMethodChannel = "method_channel" // Flutter MethodChannel("name")
	CatPlugin        = "plugin"         // Flutter plugin package names
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
	// NOTE: "slot" (singular) is absent on purpose -- it is Flutter framework
	// vocabulary (Element.slot, insertRenderObjectChild(child, slot)), and it
	// tagged _OverlayPortalElement as gambling code. "slots" is kept.
	reGambling = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(bet|wager|casino|slots|gamble|lottery|lotto|poker|roulette|jackpot|withdraw|deposit|reward|bonus|payout|cashout|spin)([^a-zA-Z]|$)`)

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
	if reBase64.MatchString(trimmed) && ShannonEntropy([]byte(value)) > 3.5 && !isCamelCase(trimmed) {
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

	// Rooting / jailbreak detection
	if containsKeyword(value, rootingKeywords) {
		cats = append(cats, CatRooting)
	}

	// Anti-analysis (anti-debug, anti-VM, anti-frida, emulator detection)
	if containsKeyword(value, antiAnalysisKeywords) {
		cats = append(cats, CatAntiAnalysis)
	}

	// SSL/TLS pinning
	if containsKeyword(value, sslPinningKeywords) {
		cats = append(cats, CatSSLPinning)
	}

	// Accessibility abuse (keylogger, screen capture)
	if containsKeyword(value, accessibilityKeywords) {
		cats = append(cats, CatAccessibility)
	}

	// Fraud / phishing / banking
	if containsKeyword(value, fraudKeywords) || reFraudShort.MatchString(value) {
		cats = append(cats, CatFraud)
	}

	// Dynamic loading
	if containsKeyword(value, dynamicLoadKeywords) {
		cats = append(cats, CatDynamicLoad)
	}

	// IPC / Binder / AIDL
	if containsKeyword(value, ipcKeywords) {
		cats = append(cats, CatIPC)
	}

	// Covert channel (Tor, proxy, DNS tunnel)
	if containsKeyword(value, covertChannelKeywords) || reCovertShort.MatchString(value) {
		cats = append(cats, CatCovertChannel)
	}

	// DRM bypass
	if containsKeyword(value, drmBypassKeywords) {
		cats = append(cats, CatDRMBypass)
	}

	// Crypto constants (AES S-box, SHA-256 K)
	if isCryptoConstant(value) {
		cats = append(cats, CatCryptoConst)
	}

	// Flutter MethodChannel
	if reMethodChannel.MatchString(value) {
		cats = append(cats, CatMethodChannel)
	}

	// Flutter plugin
	if containsKeyword(value, pluginKeywords) {
		cats = append(cats, CatPlugin)
	}

	// NOTE: CatObfuscation is deliberately NOT assigned here.
	//
	// The per-string test (2-3 characters, no vowel) cannot distinguish an
	// obfuscated identifier from an ordinary short word: on the ground-truth
	// sample it flagged "gtk" and "cvv" and nothing else, i.e. it was pure
	// noise. Obfuscation is a property of the WHOLE binary -- Dart's
	// --obfuscate renames every identifier, so what identifies it is the
	// PROPORTION of short meaningless names, not any single one. That
	// measurement is ObfuscationRatio, applied by the signal stage.

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
		"call_to_runtime", // matches both the SDK name and the old _ep spelling
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

// --- Security analysis keyword lists ---
//
// containsKeyword matches against normalizeForMatch(value), which strips
// '_', '-', ' ' and '.'. A keyword that still CONTAINS one of those
// characters can therefore never match: "frida-server", "ro.debuggable",
// "which su" and "network_security_config" were all dead on arrival.
// normalizeSecurityKeywords (init below) normalizes every list in place so a
// keyword written with separators still works; the entries are also kept in
// normalized form here to match the convention documented above.
func init() {
	for _, list := range [][]string{
		rootingKeywords, antiAnalysisKeywords, sslPinningKeywords,
		accessibilityKeywords, fraudKeywords, dynamicLoadKeywords,
		ipcKeywords, covertChannelKeywords, drmBypassKeywords, pluginKeywords,
	} {
		for i, kw := range list {
			list[i] = normalizeForMatch(kw)
		}
	}
}

var rootingKeywords = []string{
	"magisk", "supersu", "superuser", "xposed", "frida-server", "frida_server",
	"substrate", "riru", "zygisk", "busybox", "superuser.apk",
	"/system/xbin/su", "/system/bin/su", "/sbin/su", "which su",
	"chainfire", "kingroot", "kingoroot", "towelroot",
	"root_checker", "rootchecker", "isrooted", "is_rooted",
	"testkeys", "userdebug", "ro.debuggable", "ro.secure",
}

var antiAnalysisKeywords = []string{
	"ptrace", "tracerpid", "/proc/self/status", "proc/self/maps",
	"frida-gadget", "frida_gadget", "isdebuggerattached", "is_debugger_attached",
	"android.os.debug", "debug.isdebuggerconnected",
	"ro.kernel.qemu", "qemu", "qemuprops", "goldfish", "ranchu",
	"emulator", "isemulator", "is_emulator", "emulator_check",
	"anti_debug", "antidebug", "anti_debugging", "debugging_check",
	"frida", "xposed", "substrate", "cydia", "sileo",
	"hooking", "hook_detection", "detect_hook",
	"safetynet", "safety_net", "integrity_check", "playintegrity",
	"attestation", "device_integrity",
}

var sslPinningKeywords = []string{
	"certificatepinner", "certificate_pinner", "certificatepinning",
	"ssl_pinning", "sslpinning", "certpinning", "cert_pinning",
	"x509trustmanager", "x509_trust_manager", "trustmanager",
	"okhttp3.cert", "okhttp.cert", "certificatepinnercallback",
	"sha256/", "sha1/", "publickeyhash", "public_key_hash",
	"spki-pin", "spki_pin", "pins-sha256",
	"network_security_config", "networksecurityconfig",
	"cleartexttraffic", "cleartext_traffic",
}

var accessibilityKeywords = []string{
	"accessibilityservice", "accessibility_service",
	"keylogger", "key_logger", "keylog",
	"screencapture", "screen_capture", "screenshot",
	"mediaprojection", "media_projection",
	"accessibilityevent", "accessibility_event",
	"accessibilitynodeinfo", "accessibility_node_info",
	"performaction", "perform_action",
	"gesturedescription", "gesture_description",
	"dispatchgesture", "dispatch_gesture",
}

var fraudKeywords = []string{
	"phishing", "phish", "credential_harvest", "credentialharvest",
	"one_time_password", "otpbypass", "otp_bypass",
	"cardnumber", "card_number", "creditcard", "credit_card",
	"cardverification", "card_verification",
	"banking", "bank_account", "bankaccount", "iban",
	"identity_theft", "identitytheft",
	"social_security", "socialsecurity",
	"skimmer", "card_skimming", "cardskimming",
}

// Three-letter finance abbreviations need word-boundary matching, exactly
// like reCryptoShort above. As plain substrings they fire constantly on
// ordinary Flutter code: "bic" is inside "cubic" (Curves.easeInCubic, the
// Cubic curve class), "otp"/"cvc"/"ssn" inside arbitrary identifiers.
var reFraudShort = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(otp|cvv|cvc|ssn|bic)([^a-zA-Z]|$)`)

var dynamicLoadKeywords = []string{
	"dynamiclibrary", "dynamic_library", "dynamiclibrary.open",
	"loadlibrary", "load_library", "dlopen", "dlsym",
	"mirrorsystem", "mirror_system", "dart:mirrors",
	"classloader", "class_loader", "dexclassloader", "dex_class_loader",
	"pathclassloader", "path_class_loader",
	"plugin_registry", "pluginregistry",
	// "reflect" alone matched ordinary words (reflectance, reflected);
	// the specific API names below are what actually indicate reflection.
	"reflection", "invokemethod", "reflectclass",
}

var ipcKeywords = []string{
	"binder", "ibinder", "service_manager", "servicemanager",
	// "parcel"/"transact" as bare substrings matched "parcelled" and every
	// database "transaction"; the Android-specific forms are unambiguous.
	"aidl", "parcelable", "writetoparcel", "ontransact",
	"contentprovider", "content_provider", "contentresolver",
	"content_resolver", "contenturis",
	"activitymanager", "activity_manager",
	"packagemanager", "package_manager",
	"notificationmanager", "notification_manager",
	"keyguardmanager", "keyguard_manager",
	"powermanager", "power_manager",
}

var covertChannelKeywords = []string{
	// NOTE: bare "tor" is deliberately absent -- it is a substring of
	// Iterator, Constructor, Vector, Monitor, Actor and Editor, i.e. it fired
	// on most Dart core-library strings. It is matched by reCovertShort below
	// with word boundaries instead.
	"onion_router", "onionrouter", "tor_proxy", "torbrowser",
	"socks5", "socks4", "socks_proxy",
	"proxychain", "proxy_chain",
	"dns_tunnel", "dnstunnel", "iodine", "dns2tcp",
	"stunnel", "ssh_tunnel", "sshtunnel",
	"vpn_service", "vpnservice", "vpn_tunnel",
	"cloudflare_tunnel", "ngrok", "localtunnel",
}

var reCovertShort = regexp.MustCompile(`(?i)(^|[^a-zA-Z])(tor)([^a-zA-Z]|$)`)

var drmBypassKeywords = []string{
	"widevine", "fairplay", "playready",
	"drm_info", "drminfo", "drm_session", "drmsession",
	"media_drm", "mediadrm", "mediadrmmanager",
	// "provisioning" alone is generic app vocabulary; the DRM-specific
	// spelling is what identifies the category.
	"drm_provisioning", "license_request", "licenserequest",
	"key_request", "keyrequest",
	"decrypt_key", "decryptkey", "content_key", "contentkey",
}

var pluginKeywords = []string{
	"plugins.flutter.io", "io.flutter.plugins",
	"flutter_plugin", "flutterplugin",
	"plugin registrant", "pluginregistrant",
	"generated_plugin", "generatedplugin",
	"flutter_plugin_registrant",
}

var reMethodChannel = regexp.MustCompile(`(?i)methodchannel\s*\(`)

// isCryptoConstant checks if a value matches known crypto algorithm constants.
// Uses cryptoAlgorithmID from crypto_id.go as the single source of truth.
func isCryptoConstant(value string) bool {
	_, ok := cryptoAlgorithmID[strings.ToLower(strings.TrimSpace(value))]
	return ok
}

// isObfuscatedName detects short meaningless names typical of Dart --obfuscate.
// Heuristic: 1-3 char names with no vowels, or names like "aA", "bB", "xY".
// ObfuscationThreshold is the share of identifier-like strings that must look
// obfuscated before a binary is reported as obfuscated. A non-obfuscated
// Flutter app sits near zero (a handful of acronyms like "gtk"); a
// --obfuscate build renames essentially every identifier.
const ObfuscationThreshold = 0.30

// ObfuscationRatio measures how obfuscated a binary's string pool looks.
//
// It considers only identifier-like values (a name-shaped string), and returns
// the fraction of those that look like obfuscated names, the number examined,
// and up to a few examples. Callers should ignore the ratio when the
// considered count is small -- a 1-of-2 ratio says nothing.
func ObfuscationRatio(values []string) (ratio float64, considered int, samples []string) {
	for _, v := range values {
		if !isIdentifierLike(v) || len(v) > 24 {
			continue
		}
		considered++
		if isObfuscatedName(v) {
			if len(samples) < 10 {
				samples = append(samples, v)
			}
			ratio++
		}
	}
	if considered == 0 {
		return 0, 0, nil
	}
	return ratio / float64(considered), considered, samples
}

// isIdentifierLike reports whether s could be a Dart identifier: it starts
// with a letter or '_' and contains only letters, digits and '_'.
func isIdentifierLike(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func isObfuscatedName(value string) bool {
	if len(value) < 1 || len(value) > 4 {
		return false
	}
	// Only identifier-shaped strings can be obfuscated NAMES. Without this
	// gate the vowel-less test flagged every short punctuation string the
	// pool holds -- "()", "::", "{}", "->", ", " -- as obfuscation.
	if !isIdentifierLike(value) {
		return false
	}
	// All uppercase or all lowercase single char
	if len(value) == 1 && (value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z') {
		return false // single chars are common in normal code
	}
	// Check for vowel-less short names (typical of obfuscation)
	hasVowel := false
	for _, c := range value {
		switch c {
		case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
			hasVowel = true
		}
	}
	// 2-3 char names without vowels are suspicious
	if !hasVowel && len(value) >= 2 && len(value) <= 3 {
		// But exclude common short names: fn, db, id, ok, no, do, if, etc.
		commonShort := map[string]bool{"fn": true, "db": true, "id": true, "ok": true, "no": true, "do": true, "if": true, "my": true, "by": true, "tx": true, "rx": true, "dx": true, "cx": true, "ex": true, "fx": true, "gx": true, "hx": true, "ix": true, "jx": true, "kx": true, "lx": true, "mx": true, "nx": true, "ox": true, "px": true, "qx": true, "sx": true, "ux": true, "vx": true, "wx": true, "xx": true, "yx": true, "zx": true}
		if !commonShort[value] {
			return true
		}
	}
	return false
}
