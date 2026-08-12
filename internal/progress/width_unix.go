//go:build darwin || linux

package progress

import (
	"os"
	"syscall"
	"unsafe"
)

// termWidth returns the terminal's column count for f, or 0 if it cannot be
// determined (f is not a terminal, or the ioctl is unsupported). The Tracker
// uses it to clamp the redrawn line to one row so the in-place rewrite
// (carriage-return + clear-to-EOL) never wraps and stacks copies of the bar.
func termWidth(f *os.File) int {
	var ws struct {
		row, col, xpix, ypix uint16
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 {
		return 0
	}
	return int(ws.col)
}
