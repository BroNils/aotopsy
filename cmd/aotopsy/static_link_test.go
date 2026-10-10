package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestCommandDoesNotLinkNetOrCgo keeps the CLI a pure-Go executable. Importing
// "net" (even for net.ParseIP) drags in runtime/cgo; with the default
// CGO_ENABLED=1 the binary then links glibc, whose per-thread malloc arenas
// reserve ~1 GB of address space. Under the repository's mandatory
// `ulimit -v 2500000` that alone made the default pipeline die with
// "fatal error: out of memory" while the Go heap was still ~400 MB.
func TestCommandDoesNotLinkNetOrCgo(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	out, err := exec.Command(goBin, "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Skipf("go list -deps failed (offline module cache?): %v\n%s", err, out)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if pkg == "net" || pkg == "runtime/cgo" || pkg == "os/user" {
			t.Errorf("cmd/aotopsy depends on %q: use net/netip instead of net, and avoid os/user, to keep the binary cgo-free", pkg)
		}
	}
}
