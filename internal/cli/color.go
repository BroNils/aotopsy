// Package cli provides ANSI color/style constants for aotopsy's
// terminal output.
package cli

import "os"

// CRT neon palette from signal.html — BBS/Amiga aesthetic.
var (
	Green  = "\033[38;2;0;255;0m"
	Gold   = "\033[38;2;255;200;0m"
	Blue   = "\033[38;2;135;206;235m"
	Pink   = "\033[38;2;255;128;192m"
	Orange = "\033[38;2;255;128;0m"
	Red    = "\033[38;2;255;68;68m"
	Muted  = "\033[38;2;128;128;128m"
	White  = "\033[38;2;255;255;255m"
	Bold   = "\033[1m"
	Reset  = "\033[0m"
)

// DisableColor sets all color codes to empty strings.
func DisableColor() {
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
	if os.Getenv("NO_COLOR") != "" {
		DisableColor()
		return
	}
	fi, err := os.Stderr.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		DisableColor()
	}
}
