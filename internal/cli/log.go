package cli

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
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
	// A generic io.Writer has no terminal capability contract. Default it to
	// plain text unless the user explicitly forces ANSI. This prevents logs
	// written to bytes.Buffer, files wrapped in bufio.Writer, sockets, etc. from
	// inheriting terminal escapes merely because they are not *os.File.
	color := IsColorForced() && !IsColorDisabled()
	if f, ok := w.(*os.File); ok {
		color = DetectColorMode(f) != ColorNone
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
		l.write(format, args...)
	}
}

// Stage logs a formatted stage header unless quiet is enabled.
func (l *Logger) Stage(name string, format string, args ...any) {
	if !l.quiet {
		name = SafeLine(name)
		detail := l.format(format, args...)
		if l.color {
			_, _ = fmt.Fprintf(l.w, "\n%s%s%s %s\n", Pink, name, Reset, detail)
		} else {
			_, _ = fmt.Fprintf(l.w, "\n%s %s\n", name, detail)
		}
	}
}

// Warn logs a formatted warning message.
func (l *Logger) Warn(format string, args ...any) {
	msg := l.format(format, args...)
	if l.color {
		_, _ = fmt.Fprintf(l.w, "  %swarning:%s %s\n", Gold, Reset, msg)
	} else {
		_, _ = fmt.Fprintf(l.w, "  warning: %s\n", msg)
	}
}

// KV logs an aligned key-value line.
func (l *Logger) KV(key string, val any) {
	if !l.quiet {
		key = SafeLine(key)
		value := l.format("%v", val)
		if l.color {
			_, _ = fmt.Fprintf(l.w, "  %s%-12s%s %s\n", Muted, key+":", Reset, value)
		} else {
			_, _ = fmt.Fprintf(l.w, "  %-12s %s\n", key+":", value)
		}
	}
}

func (l *Logger) write(format string, args ...any) {
	_, _ = io.WriteString(l.w, l.format(format, args...))
}

func (l *Logger) format(format string, args ...any) string {
	safeArgs := make([]any, len(args))
	starArgs, runeArgs := formatSpecialArgIndexes(format)
	for i, arg := range args {
		if _, usedByStar := starArgs[i]; usedByStar {
			if _, usedAsRune := runeArgs[i]; usedAsRune {
				// A format may reuse the same explicit argument for '*' and %c,
				// for example %[1]*[1]c. It must stay a concrete int for fmt's
				// width handling, so neutralize the two controls that the final
				// sanitizer deliberately preserves as format-owned whitespace.
				if value, ok := arg.(int); ok && (value == '\n' || value == '\t') {
					safeArgs[i] = int(' ')
					continue
				}
			}
			// fmt requires dynamic width/precision operands to have the concrete
			// type int. Wrapping one in safeFormatArg turns an otherwise valid
			// directive into %!(BADWIDTH) / %!(BADPREC), so leave those operands
			// untouched. They control layout and are not rendered as text.
			safeArgs[i] = arg
			continue
		}
		if _, trusted := arg.(trustedStyle); trusted {
			safeArgs[i] = arg
			continue
		}
		_, usedAsRune := runeArgs[i]
		if shouldSanitizeFormatArg(arg) || usedAsRune && isIntegerFormatArg(arg) {
			safeArgs[i] = safeFormatArg{value: arg}
		} else {
			safeArgs[i] = arg
		}
	}
	return sanitizeTerminalText(fmt.Sprintf(format, safeArgs...), l.color)
}

// formatSpecialArgIndexes returns zero-based argument indexes consumed by '*'
// width/precision operands and by %c. fmt insists that '*' operands remain
// concrete ints, while %c needs per-argument sanitization because an integer
// can otherwise render as a newline or tab.
func formatSpecialArgIndexes(format string) (starArgs, runeArgs map[int]struct{}) {
	starArgs = make(map[int]struct{})
	runeArgs = make(map[int]struct{})
	nextArg := 0
	for i := 0; i < len(format); {
		if format[i] != '%' {
			i++
			continue
		}
		i++
		if i < len(format) && format[i] == '%' {
			i++
			continue
		}

		for i < len(format) && strings.ContainsRune("#0+- ", rune(format[i])) {
			i++
		}
		if arg, next, ok := parseFormatArgIndex(format, i); ok {
			nextArg = arg
			i = next
		}

		if i < len(format) && format[i] == '*' {
			starArgs[nextArg] = struct{}{}
			nextArg++
			i++
		} else {
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
		}

		if i < len(format) && format[i] == '.' {
			i++
			if arg, next, ok := parseFormatArgIndex(format, i); ok {
				nextArg = arg
				i = next
			}
			if i < len(format) && format[i] == '*' {
				starArgs[nextArg] = struct{}{}
				nextArg++
				i++
			} else {
				for i < len(format) && format[i] >= '0' && format[i] <= '9' {
					i++
				}
			}
		}

		if arg, next, ok := parseFormatArgIndex(format, i); ok {
			nextArg = arg
			i = next
		}
		if i < len(format) {
			verb := format[i]
			i++
			if verb != '%' {
				if verb == 'c' {
					runeArgs[nextArg] = struct{}{}
				}
				nextArg++
			}
		}
	}
	return starArgs, runeArgs
}

func parseFormatArgIndex(format string, start int) (arg int, next int, ok bool) {
	if start >= len(format) || format[start] != '[' {
		return 0, start, false
	}
	i := start + 1
	if i >= len(format) || format[i] < '1' || format[i] > '9' {
		return 0, start, false
	}
	n := 0
	for i < len(format) && format[i] >= '0' && format[i] <= '9' {
		n = n*10 + int(format[i]-'0')
		i++
	}
	if i >= len(format) || format[i] != ']' {
		return 0, start, false
	}
	return n - 1, i + 1, true
}

func isIntegerFormatArg(arg any) bool {
	if arg == nil {
		return false
	}
	switch reflect.TypeOf(arg).Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return true
	default:
		return false
	}
}

func shouldSanitizeFormatArg(arg any) bool {
	if arg == nil {
		return false
	}
	if _, ok := arg.(fmt.Formatter); ok {
		return true
	}
	if _, ok := arg.(error); ok {
		return true
	}
	if _, ok := arg.(fmt.Stringer); ok {
		return true
	}
	switch reflect.TypeOf(arg).Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Complex64, reflect.Complex128,
		reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return false
	default:
		return true
	}
}

// safeFormatArg preserves fmt's verb, flags, width and precision for an
// arbitrary value, then sanitizes only that rendered argument. This keeps
// newlines and trusted palette codes in the caller-owned format string while
// preventing data values from injecting terminal controls or extra log lines.
type safeFormatArg struct {
	value any
}

func (a safeFormatArg) Format(state fmt.State, verb rune) {
	var directive strings.Builder
	directive.WriteByte('%')
	for _, flag := range "#0+- " {
		if state.Flag(int(flag)) {
			directive.WriteRune(flag)
		}
	}
	if width, ok := state.Width(); ok {
		_, _ = fmt.Fprintf(&directive, "%d", width)
	}
	if precision, ok := state.Precision(); ok {
		directive.WriteByte('.')
		_, _ = fmt.Fprintf(&directive, "%d", precision)
	}
	directive.WriteRune(verb)
	_, _ = io.WriteString(state, SafeLine(fmt.Sprintf(directive.String(), a.value)))
}

// sanitizeTerminalText strips terminal actions from arbitrary text. When
// allowSGR is true, only the SGR forms emitted by this package's palette are
// preserved so trusted palette fragments survive. Other SGR actions such as
// conceal remain blocked even in colored logs.
// OSC, cursor movement, erase commands, RIS/DECSC, BEL, CR and DEL are always
// removed. Private-mode or other control syntax is never passed through.
func sanitizeTerminalText(s string, allowSGR bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != 0x1b {
			if s[i] < 0x20 && s[i] != '\n' && s[i] != '\t' {
				i++
				continue
			}
			if s[i] == 0x7f {
				i++
				continue
			}
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 >= len(s) {
			break
		}
		switch s[i+1] {
		case '[': // CSI: preserve only plain SGR when color is enabled.
			start := i
			i += 2
			paramsOK := true
			final := byte(0)
			for i < len(s) {
				c := s[i]
				i++
				if c >= 0x40 && c <= 0x7e {
					final = c
					break
				}
				if !((c >= '0' && c <= '9') || c == ';' || c == ':') {
					paramsOK = false
				}
			}
			if allowSGR && paramsOK && final == 'm' && isSafeSGR(s[start+2:i-1]) {
				b.WriteString(s[start:i])
			}
		case ']': // OSC: ESC ] ... BEL or ST (ESC \\)
			i += 2
			for i < len(s) {
				if s[i] == '\a' {
					i++
					break
				}
				if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
					i += 2
					break
				}
				i++
			}
		default:
			// Two-byte ESC command (RIS, DECSC, etc.).
			i += 2
		}
	}
	return b.String()
}

func isSafeSGR(params string) bool {
	if params == "" {
		return true
	}
	parts := strings.Split(params, ";")
	for i := 0; i < len(parts); {
		code, err := strconv.Atoi(parts[i])
		if err != nil {
			return false
		}
		switch {
		case code == 0 || code == 1,
			code >= 30 && code <= 37,
			code >= 90 && code <= 97:
			i++
		case code == 38 && i+2 < len(parts) && parts[i+1] == "5":
			value, err := strconv.Atoi(parts[i+2])
			if err != nil || value < 0 || value > 255 {
				return false
			}
			i += 3
		case code == 38 && i+4 < len(parts) && parts[i+1] == "2":
			for j := i + 2; j <= i+4; j++ {
				value, err := strconv.Atoi(parts[j])
				if err != nil || value < 0 || value > 255 {
					return false
				}
			}
			i += 5
		default:
			return false
		}
	}
	return true
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
