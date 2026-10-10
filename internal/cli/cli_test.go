package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestColorHex(t *testing.T) {
	tests := []struct {
		name string
		c    Color
		want string
	}{
		{"Green", greenColor, "#00FF00"},
		{"Gold", goldColor, "#FFC800"},
		{"Blue", blueColor, "#87CEEB"},
		{"Pink", pinkColor, "#FF80C0"},
		{"Orange", orangeColor, "#FF8000"},
		{"Red", redColor, "#FF4444"},
		{"Muted", mutedColor, "#808080"},
		{"White", whiteColor, "#FFFFFF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.Hex(); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestColorModes(t *testing.T) {
	// ColorTrue
	trueStr := goldColor.ANSI(ColorTrue)
	if trueStr != "\033[38;2;255;200;0m" {
		t.Errorf("unexpected truecolor: %q", trueStr)
	}

	// Color256
	c256Str := goldColor.ANSI(Color256)
	if c256Str != "\033[38;5;220m" {
		t.Errorf("unexpected 256-color: %q", c256Str)
	}

	// Color16
	c16Str := goldColor.ANSI(Color16)
	if c16Str != "\033[93m" {
		t.Errorf("unexpected 16-color: %q", c16Str)
	}

	// ColorNone
	cNoneStr := goldColor.ANSI(ColorNone)
	if cNoneStr != "" {
		t.Errorf("unexpected none color: %q", cNoneStr)
	}
}

func TestSafeLineBlocksLineAndTerminalInjection(t *testing.T) {
	got := SafeLine("bad\nforged\tfield\r\x1b[8mhidden\x1b[0m\x1b]0;title\aend")
	if got != "bad forged fieldhiddenend" {
		t.Fatalf("SafeLine = %q", got)
	}
	if strings.ContainsAny(got, "\r\n\t\x1b\a") {
		t.Fatalf("SafeLine leaked terminal control: %q", got)
	}
}

func TestSafeLineNormalizesUnicodeControlsAndMalformedUTF8(t *testing.T) {
	input := "left\u009bright\u202eabc\u2028next" + string([]byte{0xff}) + "end"
	got := SafeLine(input)
	if got != "leftrightabc next\ufffdend" {
		t.Fatalf("SafeLine unicode handling = %q", got)
	}
	if strings.ContainsAny(got, "\u009b\u202e\u2028") {
		t.Fatalf("SafeLine leaked Unicode terminal/spoofing control: %q", got)
	}
}

func TestDiagnosticBufferCapsWhileDrainingWrites(t *testing.T) {
	b := NewDiagnosticBuffer(4)
	if n, err := b.Write([]byte("abcdef")); err != nil || n != 6 {
		t.Fatalf("Write = (%d, %v), want (6, nil)", n, err)
	}
	if n, err := b.Write([]byte("gh")); err != nil || n != 2 {
		t.Fatalf("draining Write = (%d, %v), want (2, nil)", n, err)
	}
	if got := b.String(); got != "abcd [truncated]" {
		t.Fatalf("DiagnosticBuffer = %q", got)
	}
}

func TestEnvDetection(t *testing.T) {
	// IsColorForced
	t.Setenv("CLICOLOR_FORCE", "1")
	if !IsColorForced() {
		t.Errorf("expected IsColorForced true")
	}

	t.Setenv("CLICOLOR_FORCE", "0")
	if IsColorForced() {
		t.Errorf("expected IsColorForced false for 0")
	}

	t.Setenv("CLICOLOR_FORCE", "")
	if IsColorForced() {
		t.Errorf("expected IsColorForced false for empty")
	}

	// IsColorDisabled
	t.Setenv("NO_COLOR", "1")
	if !IsColorDisabled() {
		t.Errorf("expected IsColorDisabled true for NO_COLOR=1")
	}

	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "0")
	if !IsColorDisabled() {
		t.Errorf("expected IsColorDisabled true for CLICOLOR=0")
	}

	t.Setenv("CLICOLOR", "1")
	if IsColorDisabled() {
		t.Errorf("expected IsColorDisabled false for CLICOLOR=1")
	}
}

func TestDetectColorMode(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "1")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("TERM", "xterm-256color")

	// Force mode
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	if mode := DetectColorMode(nil); mode != ColorTrue {
		t.Errorf("expected ColorTrue under force+truecolor, got %v", mode)
	}

	// Disabled mode
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("NO_COLOR", "1")
	if mode := DetectColorMode(nil); mode != ColorNone {
		t.Errorf("expected ColorNone under NO_COLOR, got %v", mode)
	}

	// 256-color fallback
	t.Setenv("NO_COLOR", "")
	t.Setenv("COLORTERM", "")
	t.Setenv("TERM", "xterm-256color")
	if mode := DetectColorMode(nil); mode != Color256 {
		t.Errorf("expected Color256 under xterm-256color, got %v", mode)
	}

	// Dumb terminal
	t.Setenv("TERM", "dumb")
	if mode := DetectColorMode(nil); mode != ColorNone {
		t.Errorf("expected ColorNone under dumb, got %v", mode)
	}

	// TERM=dumb is authoritative even when COLORTERM claims truecolor.
	t.Setenv("COLORTERM", "truecolor")
	if mode := DetectColorMode(nil); mode != ColorNone {
		t.Errorf("TERM=dumb must beat COLORTERM=truecolor, got %v", mode)
	}
}

func TestDetectColorModeRejectsNonTerminalCharacterDevice(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("TERM", "xterm-256color")

	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if isTerminalFile(f) {
		t.Fatalf("%s was classified as a terminal", os.DevNull)
	}
	if mode := DetectColorMode(f); mode != ColorNone {
		t.Fatalf("DetectColorMode(%s) = %v, want ColorNone", os.DevNull, mode)
	}
}

// TestNoColorBeatsForce pins the precedence between the two conventions.
// They contradict each other by construction -- NO_COLOR says "never",
// CLICOLOR_FORCE says "no matter what" -- and the resolution is not a
// matter of taste: no-color.org is absolute and termenv's EnvNoColor
// documents that NO_COLOR is honoured "ignoring CLICOLOR/CLICOLOR_FORCE".
// Detection originally checked force first and coloured output for a user
// who had explicitly opted out.
func TestNoColorBeatsForce(t *testing.T) {
	t.Setenv("CLICOLOR", "")
	t.Setenv("COLORTERM", "truecolor")
	t.Setenv("NO_COLOR", "1")
	t.Setenv("CLICOLOR_FORCE", "1")

	if !IsColorDisabled() {
		t.Errorf("NO_COLOR must win over CLICOLOR_FORCE")
	}
	if mode := DetectColorMode(nil); mode != ColorNone {
		t.Errorf("expected ColorNone when NO_COLOR and CLICOLOR_FORCE are both set, got %v", mode)
	}
}

// TestForceBeatsCliColorZero is the other half: CLICOLOR=0 is the weaker
// request and does yield to CLICOLOR_FORCE.
func TestForceBeatsCliColorZero(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("COLORTERM", "truecolor")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("CLICOLOR", "0")
	t.Setenv("CLICOLOR_FORCE", "1")

	if IsColorDisabled() {
		t.Errorf("CLICOLOR=0 must yield to CLICOLOR_FORCE")
	}
	if mode := DetectColorMode(nil); mode != ColorTrue {
		t.Errorf("expected ColorTrue when force overrides CLICOLOR=0, got %v", mode)
	}
}

// TestForcedDumbTerminalStillGetsAnsi pins the forced-on-dumb case.
func TestForcedDumbTerminalStillGetsAnsi(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "")
	t.Setenv("COLORTERM", "")
	t.Setenv("TERM", "dumb")
	t.Setenv("CLICOLOR_FORCE", "1")

	if mode := DetectColorMode(nil); mode != Color16 {
		t.Errorf("expected Color16 on a forced dumb terminal, got %v", mode)
	}
}

func TestLogger(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.mode = ColorTrue

	// Printf
	l.Printf("hello %s\n", "world")
	if !strings.Contains(buf.String(), "hello world\n") {
		t.Errorf("expected 'hello world', got %q", buf.String())
	}
	buf.Reset()

	// Stage
	l.Stage("analysis", "%d functions", 100)
	if !strings.Contains(buf.String(), "analysis") || !strings.Contains(buf.String(), "100 functions") {
		t.Errorf("unexpected stage output: %q", buf.String())
	}
	buf.Reset()

	// Warn
	l.Warn("something strange: %s", "detail")
	if !strings.Contains(buf.String(), "warning:") || !strings.Contains(buf.String(), "something strange: detail") {
		t.Errorf("unexpected warn output: %q", buf.String())
	}
	buf.Reset()

	// KV
	l.KV("output", "/path/to/out")
	if !strings.Contains(buf.String(), "output:") || !strings.Contains(buf.String(), "/path/to/out") {
		t.Errorf("unexpected KV output: %q", buf.String())
	}
	buf.Reset()

	// Quiet mode
	lQuiet := NewLogger(&buf, true)
	lQuiet.Printf("should not appear")
	lQuiet.Stage("stage", "detail")
	lQuiet.KV("key", "val")
	if buf.Len() != 0 {
		t.Errorf("expected empty buffer in quiet mode, got %q", buf.String())
	}
	lQuiet.Warn("degraded: %s", "still visible")
	if got := buf.String(); !strings.Contains(got, "warning: degraded: still visible") {
		t.Errorf("quiet mode hid warning: %q", got)
	}
}

func TestLoggerStripsANSIForGenericWriter(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.Printf("%svalue%s\n", goldColor.ANSI(ColorTrue), "\x1b[0m")
	l.Stage("meta", "%s%d%s functions", goldColor.ANSI(ColorTrue), 7, "\x1b[0m")
	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("non-terminal writer received ANSI: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "value\n") || !strings.Contains(buf.String(), "meta 7 functions") {
		t.Fatalf("ANSI stripping damaged content: %q", buf.String())
	}
}

func TestLoggerStripsANSIForRegularFile(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	f, err := os.CreateTemp(t.TempDir(), "log-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	l := NewLogger(f, false)
	l.Printf("%sx%s\n", goldColor.ANSI(ColorTrue), "\x1b[0m")
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\x1b[") || string(b) != "x\n" {
		t.Fatalf("regular-file log = %q, want plain x\\n", b)
	}
}

func TestLoggerGenericWriterHonorsForce(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "")
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("COLORTERM", "")
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.Printf("%sx%s", Gold, Reset)
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("forced generic writer lost ANSI: %q", buf.String())
	}
}

func TestInvalidColorModeProducesNoANSI(t *testing.T) {
	if got := goldColor.ANSI(ColorMode(99)); got != "" {
		t.Fatalf("invalid color mode emitted escape residue: %q", got)
	}
}

func TestLoggerColoredModeAllowsOnlyTrustedStyle(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.mode = ColorTrue
	l.Printf("%sok%s attacker=%s\n", Gold, Reset, "\x1b[8mHIDDEN\x1b[0m\x1b]0;pwned\a\x1b[3Avisible")
	got := buf.String()
	if strings.Contains(got, "[8m") || strings.Contains(got, "]0;") || strings.Contains(got, "[3A") || strings.ContainsRune(got, '\a') {
		t.Fatalf("colored logger leaked terminal control: %q", got)
	}
	if !strings.Contains(got, goldColor.ANSI(ColorTrue)) || !strings.Contains(got, "HIDDENvisible") {
		t.Fatalf("colored logger damaged trusted SGR/content: %q", got)
	}
}

func TestLoggerRendersTrustedStyleForItsOwnMode(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.mode = Color16
	l.Printf("%sx%s", Gold, Reset)
	if got, want := buf.String(), "\x1b[93mx\x1b[0m"; got != want {
		t.Fatalf("Color16 logger output = %q, want %q", got, want)
	}
}

func TestLoggerSanitizesEachFormattedArgument(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.Printf("value=%s count=%04d ratio=%.2f padded=[%*s]\n", "one\nforged\tfield", 7, 1.25, 5, "x")
	got := buf.String()
	if got != "value=one forged field count=0007 ratio=1.25 padded=[    x]\n" {
		t.Fatalf("formatted log = %q", got)
	}
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("untrusted argument forged extra lines: %q", got)
	}
}

func TestLoggerSanitizesRuneFormattedInteger(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.Printf("value=%c end\n", '\n')
	got := buf.String()
	if got != "value=  end\n" {
		t.Fatalf("rune-formatted integer log = %q", got)
	}
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("rune-formatted integer forged extra lines: %q", got)
	}
}

func TestLoggerPreservesIntegerTypeFormatting(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.Printf("%T", 7)
	if got := buf.String(); got != "int" {
		t.Fatalf("integer type formatting = %q, want int", got)
	}
}

func TestLoggerPreservesIndexedDynamicWidthAndPrecision(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.Printf("[%[2]*.[3]*[1]s]\n", "abcdef", 5, 3)
	if got := buf.String(); got != "[  abc]\n" {
		t.Fatalf("indexed dynamic formatting = %q", got)
	}
}

func TestLoggerSanitizesRuneReusedAsDynamicWidth(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	for _, value := range []int{'\n', '\u202e'} {
		buf.Reset()
		l.Printf("value=%[1]*[1]c end\n", value)
		got := buf.String()
		if strings.Count(got, "\n") != 1 || strings.ContainsRune(got, '\u202e') {
			t.Fatalf("indexed width/rune argument %U forged terminal layout: %q", rune(value), got)
		}
	}
}

type maliciousWidth int

func (maliciousWidth) String() string {
	return "visible\nFORGED\x1b[2J\u202etext"
}

func TestLoggerSanitizesInvalidStarOperandReusedAsVisibleValue(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.Printf("value=%[1]*[1]v end\n", maliciousWidth(4))
	got := buf.String()
	if strings.Count(got, "\n") != 1 || strings.Contains(got, "\x1b[") || strings.ContainsRune(got, '\u202e') {
		t.Fatalf("reused invalid star operand forged terminal output: %q", got)
	}
	if !strings.Contains(got, "visible FORGEDtext") {
		t.Fatalf("sanitization lost printable reused argument content: %q", got)
	}
}

func TestIsTerminalFileIsFalseForClosedAndNilFiles(t *testing.T) {
	if isTerminalFile(nil) {
		t.Fatal("nil file classified as a terminal")
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if isTerminalFile(f) {
		t.Fatal("closed file classified as a terminal")
	}
}

func TestErrfSanitizesUntrustedArgumentsOnCurrentStderr(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	orig := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = orig }()

	const rlo = rune(0x202e) // right-to-left override, built from the code point on purpose
	Errf("symbol %s at 0x%x\n", "evil\nFORGED\x1b[2J"+string(rlo)+"text", 0x10)

	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if strings.Count(got, "\n") != 1 || strings.Contains(got, "\x1b[") || strings.ContainsRune(got, rlo) {
		t.Fatalf("Errf let untrusted text forge terminal output: %q", got)
	}
	if !strings.Contains(got, "symbol evil FORGEDtext at 0x10") {
		t.Fatalf("Errf lost printable content: %q", got)
	}
}
