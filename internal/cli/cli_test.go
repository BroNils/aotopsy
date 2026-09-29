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
		{"Green", GreenColor, "#00FF00"},
		{"Gold", GoldColor, "#FFC800"},
		{"Blue", BlueColor, "#87CEEB"},
		{"Pink", PinkColor, "#FF80C0"},
		{"Orange", OrangeColor, "#FF8000"},
		{"Red", RedColor, "#FF4444"},
		{"Muted", MutedColor, "#808080"},
		{"White", WhiteColor, "#FFFFFF"},
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
	trueStr := GoldColor.ANSI(ColorTrue)
	if trueStr != "\033[38;2;255;200;0m" {
		t.Errorf("unexpected truecolor: %q", trueStr)
	}

	// Color256
	c256Str := GoldColor.ANSI(Color256)
	if c256Str != "\033[38;5;220m" {
		t.Errorf("unexpected 256-color: %q", c256Str)
	}

	// Color16
	c16Str := GoldColor.ANSI(Color16)
	if c16Str != "\033[93m" {
		t.Errorf("unexpected 16-color: %q", c16Str)
	}

	// ColorNone
	cNoneStr := GoldColor.ANSI(ColorNone)
	if cNoneStr != "" {
		t.Errorf("unexpected none color: %q", cNoneStr)
	}
}

func TestColorWrapAndFormat(t *testing.T) {
	origMode := currentMode
	defer SetColorMode(origMode)

	// Enabled
	SetColorMode(ColorTrue)
	s := GoldColor.S("test")
	if !strings.HasPrefix(s, "\033[38;2;255;200;0m") || !strings.HasSuffix(s, string(Reset)) {
		t.Errorf("unexpected colored wrap: %q", s)
	}

	f := GoldColor.F("%d values", 42)
	if !strings.Contains(f, "42 values") || !strings.HasSuffix(f, string(Reset)) {
		t.Errorf("unexpected colored format: %q", f)
	}

	// Disabled
	SetColorMode(ColorNone)
	sDisabled := GoldColor.S("plain")
	if sDisabled != "plain" {
		t.Errorf("expected plain text when disabled, got %q", sDisabled)
	}

	fDisabled := GoldColor.F("%d values", 42)
	if fDisabled != "42 values" {
		t.Errorf("expected plain text when disabled, got %q", fDisabled)
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
	l.color = true

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
}

func TestMakeLogfAndMakeStagef(t *testing.T) {
	var buf bytes.Buffer
	logf := MakeLogf(false, &buf)
	logf("msg: %d\n", 123)
	if buf.String() != "msg: 123\n" {
		t.Errorf("unexpected logf output: %q", buf.String())
	}
	buf.Reset()

	stagef := MakeStagef(false, &buf)
	stagef("myStage", "count=%d", 5)
	if !strings.Contains(buf.String(), "myStage") || !strings.Contains(buf.String(), "count=5") {
		t.Errorf("unexpected stagef output: %q", buf.String())
	}
}

func TestLoggerStripsANSIForGenericWriter(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.Printf("%svalue%s\n", GoldColor.ANSI(ColorTrue), "\x1b[0m")
	l.Stage("meta", "%s%d%s functions", GoldColor.ANSI(ColorTrue), 7, "\x1b[0m")
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
	l.Printf("%sx%s\n", GoldColor.ANSI(ColorTrue), "\x1b[0m")
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
	orig := currentMode
	defer SetColorMode(orig)
	SetColorMode(Color16)
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.Printf("%sx%s", Gold, Reset)
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("forced generic writer lost ANSI: %q", buf.String())
	}
}

func TestInvalidColorModeNormalizesToNone(t *testing.T) {
	orig := currentMode
	defer SetColorMode(orig)
	SetColorMode(ColorMode(99))
	if currentMode != ColorNone {
		t.Fatalf("invalid mode normalized to %v, want ColorNone", currentMode)
	}
	if got := GoldColor.S("x"); got != "x" {
		t.Fatalf("invalid mode emitted escape residue: %q", got)
	}
}

func TestTerminalSanitizationBlocksControlInjectionWithColor(t *testing.T) {
	orig := currentMode
	defer SetColorMode(orig)
	SetColorMode(ColorTrue)

	malicious := "name\x1b]8;;https://evil.invalid\aCLICK\x1b]8;;\a\x1b[2J\x1b[H\a\rrest"
	got := GoldColor.S(malicious)
	if strings.Contains(got, "]8;") || strings.Contains(got, "[2J") || strings.Contains(got, "[H") || strings.ContainsAny(got, "\a\r") {
		t.Fatalf("Color.S leaked terminal action: %q", got)
	}
	if !strings.Contains(got, "nameCLICKrest") {
		t.Fatalf("sanitization lost printable content: %q", got)
	}
	// The wrapper's own SGR color must remain intact.
	if !strings.HasPrefix(got, GoldColor.ANSI(ColorTrue)) || !strings.HasSuffix(got, string(Reset)) {
		t.Fatalf("trusted color wrapper was stripped: %q", got)
	}
}

func TestLoggerColoredModeAllowsOnlyTrustedStyle(t *testing.T) {
	orig := currentMode
	defer SetColorMode(orig)
	SetColorMode(ColorTrue)
	var buf bytes.Buffer
	l := NewLogger(&buf, false)
	l.color = true
	l.Printf("%sok%s attacker=%s\n", Gold, Reset, "\x1b[8mHIDDEN\x1b[0m\x1b]0;pwned\a\x1b[3Avisible")
	got := buf.String()
	if strings.Contains(got, "[8m") || strings.Contains(got, "]0;") || strings.Contains(got, "[3A") || strings.ContainsRune(got, '\a') {
		t.Fatalf("colored logger leaked terminal control: %q", got)
	}
	if !strings.Contains(got, GoldColor.ANSI(ColorTrue)) || !strings.Contains(got, "HIDDENvisible") {
		t.Fatalf("colored logger damaged trusted SGR/content: %q", got)
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
	l.Printf("value=%[1]*[1]c end\n", int('\n'))
	got := buf.String()
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("indexed width/rune argument forged extra lines: %q", got)
	}
}
