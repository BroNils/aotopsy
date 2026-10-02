//go:build !windows

package elfx

import "os"

// platformFileChangeTime is reserved for platforms whose os.FileInfo does not
// expose a usable status-change timestamp. Unix-like systems fall back to the
// ctime fields decoded from FileInfo.Sys in fileChangeTime.
func platformFileChangeTime(_ *os.File) (int64, bool) {
	return 0, false
}
