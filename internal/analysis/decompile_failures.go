package analysis

import (
	"fmt"
	"io"
	"path/filepath"

	"aotopsy/internal/jsonutil"
)

// DecompileFailuresFile is the artifact that lists every function a batch
// decompile could not produce. An empty file means the batch was complete.
const DecompileFailuresFile = "decompile_failures.jsonl"

// DecompileFailure is one function a batch decompile skipped.
type DecompileFailure struct {
	PC     string `json:"pc"`
	RefID  int    `json:"ref_id"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason"`
}

// FailureLog decides what a per-function failure means for a batch. One broken
// function must not discard the other ~128k, so by default it is recorded and
// the batch continues; Strict restores fail-on-first for CI. Either way the
// failure is never silent: Finish writes the list and states the count.
type FailureLog struct {
	Strict bool
	items  []DecompileFailure
}

// Record notes a failure. In strict mode it returns the error that must abort
// the batch; otherwise it returns nil and the caller continues.
func (l *FailureLog) Record(pc uint64, refID int, name string, err error) error {
	if l.Strict {
		return fmt.Errorf("decompile 0x%x ref=%d %s: %w", pc, refID, name, err)
	}
	l.items = append(l.items, DecompileFailure{
		PC: fmt.Sprintf("0x%x", pc), RefID: refID, Name: name, Reason: err.Error(),
	})
	return nil
}

// Count is the number of skipped functions.
func (l *FailureLog) Count() int { return len(l.items) }

// Finish reports the count on w and, when dir is set, atomically writes
// DecompileFailuresFile there (an empty file when nothing failed, so a stale
// list from an earlier run cannot survive).
func (l *FailureLog) Finish(dir string, w io.Writer) error {
	if dir != "" {
		items := l.items
		if items == nil {
			items = []DecompileFailure{}
		}
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, DecompileFailuresFile), items); err != nil {
			return fmt.Errorf("write %s: %w", DecompileFailuresFile, err)
		}
	}
	if len(l.items) > 0 {
		fmt.Fprintf(w, "WARNING: %d function(s) could not be decompiled and were skipped (see %s; use --strict to fail instead)\n",
			len(l.items), DecompileFailuresFile)
	}
	return nil
}
