package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/progress"
)

// flagGroup is a titled set of flags rendered together, in the given order, within
// a command's usage output. Each entry is a flag's primary (long) name; an aliased
// short form (e.g. -o for --output) is discovered automatically and folded onto the
// same line, so a group lists each flag once.
type flagGroup struct {
	title string
	names []string
}

const (
	// descCol is the column (0-based) where flag descriptions begin. Labels wider
	// than this push their description onto the next line.
	descCol = 26
	// usageIndent is the left margin before each flag label.
	usageIndent = 2
	// fallbackCols is the assumed line width when the terminal size is unknown
	// (output is redirected, or the ioctl is unsupported); minCols floors a very
	// narrow terminal so wrapping stays sane.
	fallbackCols = 80
	minCols      = 40
)

// setGroupedUsage installs fs.Usage to print header, then fs's flags organized
// under the given groups in a two-column, width-aware layout — descriptions are
// aligned at descCol and wrapped to the terminal width with a hanging indent, so
// long help text no longer hard-wraps back to column 0 — then footer. Any flag not
// listed in a group is appended under an "Other" group, so a newly added flag is
// never silently dropped from the help.
func setGroupedUsage(fs *flag.FlagSet, header, footer string, groups []flagGroup) {
	fs.Usage = func() {
		w := fs.Output()
		writeBlock(w, header)

		// Group flags by shared Value pointer so aliases (-o/--output, bound to the
		// same variable) fold onto one line, and index them by name for lookup.
		aliases := map[flag.Value][]string{}
		byName := map[string]*flag.Flag{}
		fs.VisitAll(func(f *flag.Flag) {
			aliases[f.Value] = append(aliases[f.Value], f.Name)
			byName[f.Name] = f
		})

		printed := map[string]bool{}
		cols := terminalCols(w)

		render := func(g flagGroup) {
			type row struct{ label, desc string }
			var rows []row
			for _, name := range g.names {
				f := byName[name]
				if f == nil || printed[name] {
					continue
				}
				names := append([]string(nil), aliases[f.Value]...)
				for _, n := range names {
					printed[n] = true
				}
				rows = append(rows, row{flagLabel(f, names), flagDesc(f)})
			}
			if len(rows) == 0 {
				return
			}
			fmt.Fprintf(w, "\n%s:\n", g.title)
			for _, r := range rows {
				writeFlagRow(w, r.label, r.desc, cols)
			}
		}

		for _, g := range groups {
			render(g)
		}

		// Anything not placed in a group falls through to "Other" so help stays
		// complete even if a flag is added without updating the groups.
		var leftover []string
		fs.VisitAll(func(f *flag.Flag) {
			if !printed[f.Name] {
				leftover = append(leftover, f.Name)
			}
		})
		if len(leftover) > 0 {
			sort.Strings(leftover)
			render(flagGroup{"Other", leftover})
		}

		if footer != "" {
			fmt.Fprintln(w)
			writeBlock(w, footer)
		}
	}
}

// flagLabel renders a flag's invocation column: its names (single-letter forms with
// one dash, long forms with two), shortest first, joined with ", ", followed by the
// value placeholder ("string", "int", …) for non-boolean flags.
func flagLabel(f *flag.Flag, names []string) string {
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})
	parts := make([]string, len(names))
	for i, n := range names {
		if len(n) == 1 {
			parts[i] = "-" + n
		} else {
			parts[i] = "--" + n
		}
	}
	label := strings.Join(parts, ", ")
	if typ, _ := flag.UnquoteUsage(f); typ != "" {
		label += " " + typ
	}
	return label
}

// flagDesc is a flag's help text with its default value appended in the same form
// the standard library uses — but only when the default differs from the type's
// zero value, so custom flags that already spell their default into the help text
// (e.g. "(default: all)") don't also get a redundant "(default …)".
func flagDesc(f *flag.Flag) string {
	typ, usage := flag.UnquoteUsage(f)
	if isZeroDefault(f) {
		return usage
	}
	if typ == "string" {
		return usage + fmt.Sprintf(" (default %q)", f.DefValue)
	}
	return usage + fmt.Sprintf(" (default %s)", f.DefValue)
}

// isZeroDefault reports whether f's default equals the zero value for its flag
// type, mirroring the standard library's flag.isZeroValue so a default is appended
// under exactly the conditions flag.PrintDefaults would.
func isZeroDefault(f *flag.Flag) bool {
	typ := reflect.TypeOf(f.Value)
	if typ == nil {
		return f.DefValue == ""
	}
	var z reflect.Value
	if typ.Kind() == reflect.Pointer {
		z = reflect.New(typ.Elem())
	} else {
		z = reflect.Zero(typ)
	}
	zv, ok := z.Interface().(flag.Value)
	if !ok {
		return f.DefValue == ""
	}
	return f.DefValue == zv.String()
}

// writeFlagRow prints one flag: its label at usageIndent, then its description
// aligned at descCol and wrapped to cols columns with a hanging indent, so
// continuation lines line up under the first. A label wider than descCol pushes the
// description onto the next line rather than crowding it.
func writeFlagRow(w io.Writer, label, desc string, cols int) {
	writeTwoColRow(w, label, desc, descCol, cols)
}

// writeTwoColRow prints a two-column row: label at usageIndent, then desc aligned
// at column col and wrapped to cols columns with a hanging indent so continuation
// lines line up under the first desc line. A label that reaches col pushes the
// description onto the next line rather than crowding it. It is the shared layout
// primitive behind both the flag groups (col = descCol) and the top-level command
// list (col sized to the widest command name).
func writeTwoColRow(w io.Writer, label, desc string, col, cols int) {
	lead := strings.Repeat(" ", usageIndent) + label
	pad := col - len(lead)
	if pad < 1 {
		fmt.Fprintln(w, lead)
		lead, pad = "", col
	}
	wrapWidth := cols - col
	if wrapWidth < 20 {
		wrapWidth = 20
	}
	lines := wrapText(desc, wrapWidth)
	if len(lines) == 0 {
		fmt.Fprintln(w, lead)
		return
	}
	fmt.Fprintf(w, "%s%s%s\n", lead, strings.Repeat(" ", pad), lines[0])
	hang := strings.Repeat(" ", col)
	for _, ln := range lines[1:] {
		fmt.Fprintf(w, "%s%s\n", hang, ln)
	}
}

// wrapText greedily wraps s to at most width columns per line, breaking only at
// spaces (a word longer than width overflows on its own line rather than being
// split).
func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	lines := []string{words[0]}
	for _, wd := range words[1:] {
		last := len(lines) - 1
		if len(lines[last])+1+len(wd) <= width {
			lines[last] += " " + wd
		} else {
			lines = append(lines, wd)
		}
	}
	return lines
}

// terminalCols is the wrap width for usage: the terminal's column count when w is
// a terminal, else fallbackCols. A very narrow terminal is floored at minCols.
func terminalCols(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		if c := progress.TermWidth(f); c > 0 {
			if c < minCols {
				return minCols
			}
			return c
		}
	}
	return fallbackCols
}

// writeWrapped prints a blank separator line, then s wrapped to cols columns at
// the left margin — for prose paragraphs in the top-level usage that should reflow
// to the terminal width instead of hard-wrapping at a fixed column.
func writeWrapped(w io.Writer, s string, cols int) {
	fmt.Fprintln(w)
	for _, ln := range wrapText(s, cols) {
		fmt.Fprintln(w, ln)
	}
}

// writeBlock writes s and guarantees it ends with exactly one newline.
func writeBlock(w io.Writer, s string) {
	fmt.Fprint(w, s)
	if !strings.HasSuffix(s, "\n") {
		fmt.Fprintln(w)
	}
}
