package cli

// DefaultDiagnosticCaptureLimit bounds output captured from external tools
// before it is rendered as a terminal diagnostic. The writer always reports a
// full successful write so the child process keeps draining instead of
// deadlocking after the retained prefix reaches the cap.
const DefaultDiagnosticCaptureLimit = 64 << 10

// DiagnosticBuffer retains at most limit bytes while continuing to drain all
// writes. It is intended for diagnostic subprocess output, not semantic data.
type DiagnosticBuffer struct {
	data      []byte
	limit     int
	truncated bool
}

func NewDiagnosticBuffer(limit int) *DiagnosticBuffer {
	if limit <= 0 {
		limit = DefaultDiagnosticCaptureLimit
	}
	return &DiagnosticBuffer{limit: limit}
}

func (b *DiagnosticBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - len(b.data)
	if remaining <= 0 {
		b.truncated = true
		return n, nil
	}
	if len(p) > remaining {
		b.data = append(b.data, p[:remaining]...)
		b.truncated = true
		return n, nil
	}
	b.data = append(b.data, p...)
	return n, nil
}

func (b *DiagnosticBuffer) String() string {
	if !b.truncated {
		return string(b.data)
	}
	return string(b.data) + " [truncated]"
}
