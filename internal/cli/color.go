// Package cli provides ANSI color/style constants, terminal capability detection,
// and formatted logging for aotopsy's terminal output.
package cli

import (
	"fmt"
	"os"
	"strings"
	"unicode"
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

// SafeLine makes untrusted text safe for one terminal line. Terminal escape
// sequences and terminal controls are removed; embedded line separators and
// tabs become spaces so an argument, path or error cannot forge extra output
// lines. Bidirectional formatting controls are dropped to keep visually-spoofed
// terminal text from reordering trusted labels around untrusted data. Malformed
// UTF-8 is normalized to U+FFFD by strings.Map. Ordinary Unicode is preserved.
func SafeLine(text string) string {
	text = sanitizeTerminalText(text, false)
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\t', '\u2028', '\u2029':
			return ' '
		}
		if unicode.IsControl(r) || isBidiControl(r) {
			return -1
		}
		return r
	}, text)
}

func isBidiControl(r rune) bool {
	switch r {
	case '\u061c', '\u200e', '\u200f',
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069':
		return true
	default:
		return false
	}
}

var (
	greenColor  = Color{0, 255, 0, 46, "\033[92m"}
	goldColor   = Color{255, 200, 0, 220, "\033[93m"}
	blueColor   = Color{135, 206, 235, 117, "\033[96m"}
	pinkColor   = Color{255, 128, 192, 217, "\033[95m"}
	orangeColor = Color{255, 128, 0, 208, "\033[33m"}
	redColor    = Color{255, 68, 68, 196, "\033[91m"}
	mutedColor  = Color{128, 128, 128, 244, "\033[90m"}
	whiteColor  = Color{255, 255, 255, 231, "\033[97m"}
)

// style is an immutable semantic formatting token understood by Logger. It is
// deliberately not a raw escape string: the logger renders it for the actual
// destination writer, so terminal capability is never inherited from some
// unrelated global stream. Callers receive only the exported constants below,
// so arbitrary data cannot be cast into a trusted style token.
type style uint8

const (
	Green style = iota
	Gold
	Blue
	Pink
	Orange
	Red
	Muted
	White
	Bold
	Reset
)

func (s style) ansi(mode ColorMode) string {
	if mode == ColorNone {
		return ""
	}
	switch s {
	case Green:
		return greenColor.ANSI(mode)
	case Gold:
		return goldColor.ANSI(mode)
	case Blue:
		return blueColor.ANSI(mode)
	case Pink:
		return pinkColor.ANSI(mode)
	case Orange:
		return orangeColor.ANSI(mode)
	case Red:
		return redColor.ANSI(mode)
	case Muted:
		return mutedColor.ANSI(mode)
	case White:
		return whiteColor.ANSI(mode)
	case Bold:
		return "\033[1m"
	case Reset:
		return "\033[0m"
	default:
		return ""
	}
}

// IsColorDisabled reports whether the environment asks for no color,
// resolving the two conventions against each other the way they are
// actually specified.
//
// NO_COLOR (https://no-color.org/) is absolute: set and non-empty means no
// color, and CLICOLOR_FORCE does not override it. CLICOLOR=0
// (https://bixense.com/clicolors/) is the weaker request -- it yields to
// CLICOLOR_FORCE.
//
// The first version of this checked CLICOLOR_FORCE before NO_COLOR, so
// `NO_COLOR=1 CLICOLOR_FORCE=1` emitted escapes at a user who had said not
// to. Ordering matched against muesli/termenv, whose EnvNoColor documents
// exactly this precedence.
func IsColorDisabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	return os.Getenv("CLICOLOR") == "0" && !IsColorForced()
}

// IsColorForced checks CLICOLOR_FORCE convention.
func IsColorForced() bool {
	v := os.Getenv("CLICOLOR_FORCE")
	return v != "" && v != "0"
}

// DetectColorMode determines terminal capability from environment and output stream.
func DetectColorMode(f *os.File) ColorMode {
	if IsColorDisabled() {
		return ColorNone
	}
	forced := IsColorForced()
	// A forced run skips the TTY test -- that is the whole point of the
	// flag: piping into a pager or a CI log that renders escapes.
	if !forced && f != nil {
		if !isTerminalFile(f) {
			return ColorNone
		}
	}
	term := os.Getenv("TERM")
	if term == "dumb" {
		// TERM=dumb is an explicit statement that the terminal has no color
		// capability. COLORTERM/24-bit hints must not override it. A forced run
		// still gets basic ANSI, matching the force contract.
		if forced {
			return Color16
		}
		return ColorNone
	}
	if isTrueColorSupported() {
		return ColorTrue
	}
	if strings.Contains(term, "256color") {
		return Color256
	}
	return Color16
}

func isTrueColorSupported() bool {
	term := os.Getenv("TERM")
	ct := os.Getenv("COLORTERM")
	return strings.Contains(term, "24bit") || strings.Contains(term, "truecolor") ||
		strings.Contains(ct, "24bit") || strings.Contains(ct, "truecolor")
}
