package progress

import "os"

// TermWidth returns the terminal's column count for f, or 0 if it cannot be
// determined (f is not a terminal, or the platform lacks the TIOCGWINSZ ioctl).
// It exposes the same measurement the progress Tracker uses so other packages
// (e.g. the CLI usage printer) can wrap output to the real terminal width.
func TermWidth(f *os.File) int { return termWidth(f) }
