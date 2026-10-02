//go:build windows

package elfx

import (
	"os"
	"syscall"
	"unsafe"
)

// FILE_BASIC_INFO from WinBase.h. ChangeTime is maintained separately from
// LastWriteTime and cannot be reset through ordinary SetFileTime calls that
// restore mtime after a write.
type windowsFileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

var windowsGetFileInformationByHandleEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFileInformationByHandleEx")

func platformFileChangeTime(file *os.File) (int64, bool) {
	if file == nil {
		return 0, false
	}
	var info windowsFileBasicInfo
	const fileBasicInfoClass = uintptr(0)
	r1, _, _ := windowsGetFileInformationByHandleEx.Call(
		file.Fd(),
		fileBasicInfoClass,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r1 == 0 {
		return 0, false
	}
	return info.ChangeTime, true
}
