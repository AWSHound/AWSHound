//go:build !darwin && !linux

package progress

import "os"

// termWidth is a no-op on platforms without the TIOCGWINSZ ioctl; returning 0
// disables line clamping (the redraw falls back to emitting the full line).
func termWidth(f *os.File) int { return 0 }
