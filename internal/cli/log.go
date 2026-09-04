package cli

import (
	"fmt"
	"io"
	"os"
)

// Logger provides structured, formatted logging to a designated writer.
type Logger struct {
	w     io.Writer
	quiet bool
	color bool
}

// NewLogger creates a new Logger writing to w with color awareness.
func NewLogger(w io.Writer, quiet bool) *Logger {
	if w == nil {
		w = io.Discard
	}
	color := true
	if f, ok := w.(*os.File); ok {
		color = DetectColorMode(f) != ColorNone
	} else if IsColorDisabled() && !IsColorForced() {
		color = false
	}
	return &Logger{
		w:     w,
		quiet: quiet,
		color: color,
	}
}

// Printf logs formatted output unless quiet is enabled.
func (l *Logger) Printf(format string, args ...any) {
	if !l.quiet {
		_, _ = fmt.Fprintf(l.w, format, args...)
	}
}

// Stage logs a formatted stage header unless quiet is enabled.
func (l *Logger) Stage(name string, format string, args ...any) {
	if !l.quiet {
		detail := fmt.Sprintf(format, args...)
		if l.color {
			_, _ = fmt.Fprintf(l.w, "\n%s%s%s %s\n", Pink, name, Reset, detail)
		} else {
			_, _ = fmt.Fprintf(l.w, "\n%s %s\n", name, detail)
		}
	}
}

// Warn logs a formatted warning message.
func (l *Logger) Warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if l.color {
		_, _ = fmt.Fprintf(l.w, "  %swarning:%s %s\n", Gold, Reset, msg)
	} else {
		_, _ = fmt.Fprintf(l.w, "  warning: %s\n", msg)
	}
}

// KV logs an aligned key-value line.
func (l *Logger) KV(key string, val any) {
	if !l.quiet {
		if l.color {
			_, _ = fmt.Fprintf(l.w, "  %s%-12s%s %v\n", Muted, key+":", Reset, val)
		} else {
			_, _ = fmt.Fprintf(l.w, "  %-12s %v\n", key+":", val)
		}
	}
}

// MakeLogf returns a closure that writes to log only when !quiet.
func MakeLogf(quiet bool, log io.Writer) func(string, ...any) {
	l := NewLogger(log, quiet)
	return l.Printf
}

// MakeStagef returns a closure that writes a stage header to log only when !quiet.
func MakeStagef(quiet bool, log io.Writer) func(string, string, ...any) {
	l := NewLogger(log, quiet)
	return l.Stage
}
