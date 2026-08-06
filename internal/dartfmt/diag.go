// Package dartfmt provides shared types and diagnostics for Dart snapshot parsing.
package dartfmt

import "fmt"

// DiagKind classifies a diagnostic message.
type DiagKind string

const (
	DiagTruncated  DiagKind = "truncated"
	DiagInvalid    DiagKind = "invalid"
	DiagUnknownTag DiagKind = "unknown_tag"
	DiagOverflow   DiagKind = "overflow"
	DiagClamped    DiagKind = "clamped"
)

// Diag records a non-fatal issue encountered during parsing.
type Diag struct {
	Offset uint64   `json:"offset"`
	Kind   DiagKind `json:"kind"`
	Msg    string   `json:"msg"`
}

func (d Diag) String() string {
	return fmt.Sprintf("[%s] 0x%x: %s", d.Kind, d.Offset, d.Msg)
}

// Diags accumulates diagnostics.
type Diags struct {
	items []Diag
}

func (d *Diags) Add(offset uint64, kind DiagKind, msg string) {
	d.items = append(d.items, Diag{Offset: offset, Kind: kind, Msg: msg})
}

func (d *Diags) Addf(offset uint64, kind DiagKind, format string, args ...any) {
	d.items = append(d.items, Diag{Offset: offset, Kind: kind, Msg: fmt.Sprintf(format, args...)})
}

func (d *Diags) Items() []Diag { return d.items }
func (d *Diags) Len() int      { return len(d.items) }

// Mode controls error handling behavior.
type Mode int

const (
	ModeStrict     Mode = iota // first structural error returns error
	ModeBestEffort             // continue with placeholders, accumulate diags
)

// Options controls parsing behavior across packages.
type Options struct {
	Mode     Mode
	MaxSteps int // global loop cap; 0 = use default
	MaxBytes int // output size cap; 0 = unlimited
}

// DefaultMaxSteps is the global default loop cap.
const DefaultMaxSteps = 10_000_000

func (o Options) EffectiveMaxSteps() int {
	if o.MaxSteps > 0 {
		return o.MaxSteps
	}
	return DefaultMaxSteps
}
