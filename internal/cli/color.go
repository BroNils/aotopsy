// Package cli provides ANSI color/style constants, terminal capability detection,
// and formatted logging for aotopsy's terminal output.
package cli

import (
	"fmt"
	"os"
	"strings"
)

// ColorMode specifies terminal color capability.
type ColorMode int

const (
	ColorNone ColorMode = iota
	Color16
	Color256
	ColorTrue
)

// Color defines an RGB color with 256-color and 16-color fallbacks.
type Color struct {
	R, G, B uint8
	Code256 uint8
	Code16  string
}

// Hex returns the CSS hex representation, e.g. "#FFC800".
func (c Color) Hex() string {
	return fmt.Sprintf("#%02X%02X%02X", c.R, c.G, c.B)
}

// ANSI returns the ANSI escape string according to the given ColorMode.
func (c Color) ANSI(mode ColorMode) string {
	switch mode {
	case ColorTrue:
		return fmt.Sprintf("\033[38;2;%d;%d;%dm", c.R, c.G, c.B)
	case Color256:
		return fmt.Sprintf("\033[38;5;%dm", c.Code256)
	case Color16:
		return c.Code16
	default:
		return ""
	}
}

// S wraps text with this color and Reset if color is enabled.
func (c Color) S(text string) string {
	if currentMode == ColorNone || text == "" {
		return text
	}
	return c.ANSI(currentMode) + text + Reset
}

// F formats text with this color and Reset if color is enabled.
func (c Color) F(format string, args ...any) string {
	return c.S(fmt.Sprintf(format, args...))
}

var (
	GreenColor  = Color{0, 255, 0, 46, "\033[92m"}
	GoldColor   = Color{255, 200, 0, 220, "\033[93m"}
	BlueColor   = Color{135, 206, 235, 117, "\033[96m"}
	PinkColor   = Color{255, 128, 192, 217, "\033[95m"}
	OrangeColor = Color{255, 128, 0, 208, "\033[33m"}
	RedColor    = Color{255, 68, 68, 196, "\033[91m"}
	MutedColor  = Color{128, 128, 128, 244, "\033[90m"}
	WhiteColor  = Color{255, 255, 255, 231, "\033[97m"}
)

// CRT neon palette from signal.html — BBS/Amiga aesthetic.
var (
	Green  = GreenColor.ANSI(ColorTrue)
	Gold   = GoldColor.ANSI(ColorTrue)
	Blue   = BlueColor.ANSI(ColorTrue)
	Pink   = PinkColor.ANSI(ColorTrue)
	Orange = OrangeColor.ANSI(ColorTrue)
	Red    = RedColor.ANSI(ColorTrue)
	Muted  = MutedColor.ANSI(ColorTrue)
	White  = WhiteColor.ANSI(ColorTrue)
	Bold   = "\033[1m"
	Reset  = "\033[0m"
)

var currentMode = ColorTrue

// IsColorDisabled checks NO_COLOR and CLICOLOR conventions.
func IsColorDisabled() bool {
	return os.Getenv("NO_COLOR") != "" || os.Getenv("CLICOLOR") == "0"
}

// IsColorForced checks CLICOLOR_FORCE convention.
func IsColorForced() bool {
	v := os.Getenv("CLICOLOR_FORCE")
	return v != "" && v != "0"
}

// DetectColorMode determines terminal capability from environment and output stream.
func DetectColorMode(f *os.File) ColorMode {
	if IsColorForced() {
		if isTrueColorSupported() {
			return ColorTrue
		}
		return Color256
	}
	if IsColorDisabled() {
		return ColorNone
	}
	if f != nil {
		fi, err := f.Stat()
		if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
			return ColorNone
		}
	}
	if isTrueColorSupported() {
		return ColorTrue
	}
	term := os.Getenv("TERM")
	if strings.Contains(term, "256color") {
		return Color256
	}
	if term == "dumb" {
		return ColorNone
	}
	return Color16
}

func isTrueColorSupported() bool {
	term := os.Getenv("TERM")
	ct := os.Getenv("COLORTERM")
	return strings.Contains(term, "24bit") || strings.Contains(term, "truecolor") ||
		strings.Contains(ct, "24bit") || strings.Contains(ct, "truecolor")
}

// SetColorMode updates global escape strings to match the desired ColorMode.
func SetColorMode(mode ColorMode) {
	currentMode = mode
	if mode == ColorNone {
		DisableColor()
		return
	}
	Green = GreenColor.ANSI(mode)
	Gold = GoldColor.ANSI(mode)
	Blue = BlueColor.ANSI(mode)
	Pink = PinkColor.ANSI(mode)
	Orange = OrangeColor.ANSI(mode)
	Red = RedColor.ANSI(mode)
	Muted = MutedColor.ANSI(mode)
	White = WhiteColor.ANSI(mode)
	Bold = "\033[1m"
	Reset = "\033[0m"
}

// DisableColor sets all color codes to empty strings.
func DisableColor() {
	currentMode = ColorNone
	Green = ""
	Gold = ""
	Blue = ""
	Pink = ""
	Orange = ""
	Red = ""
	Muted = ""
	White = ""
	Bold = ""
	Reset = ""
}

func init() {
	SetColorMode(DetectColorMode(os.Stderr))
}
