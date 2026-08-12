package model

// fnmatch reports whether name matches an fnmatch-style glob pattern, honoring
// '*' (any run, including '/'), '?' (any one rune), and '[seq]'/'[!seq]' character
// classes — the subset of CPython fnmatch.fnmatch semantics the S3 filter's "glob"
// operator uses. It is case-sensitive (POSIX os.path.normcase is identity), matching
// how the Python tool runs. The eval package carries an equivalent matcher for IAM
// action/ARN globs; this copy keeps the low-level model package free of that
// dependency.
func fnmatch(name, pattern string) bool {
	return matchGlob([]rune(name), []rune(pattern))
}

// matchGlob is a linear two-pointer glob matcher with a single backtrack point for
// '*', giving O(len(name)*len(pattern)) worst case and no catastrophic backtracking.
func matchGlob(name, pat []rune) bool {
	ni, pi := 0, 0
	starPi, starNi := -1, -1
	for ni < len(name) {
		if pi < len(pat) && pat[pi] == '*' {
			// Collapse consecutive '*'.
			for pi < len(pat) && pat[pi] == '*' {
				pi++
			}
			starPi, starNi = pi, ni
			continue
		}
		if pi < len(pat) && matchGlobOne(pat, &pi, name[ni]) {
			ni++
			continue
		}
		if starPi >= 0 {
			pi = starPi
			starNi++
			ni = starNi
			continue
		}
		return false
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}

// matchGlobOne tests the single-rune token at pat[*pi] against ch, advancing *pi
// past that token (a literal, '?', or a '[...]' class). It never sees '*' (handled
// by the caller). Returns false without advancing when the token cannot match.
func matchGlobOne(pat []rune, pi *int, ch rune) bool {
	c := pat[*pi]
	switch c {
	case '?':
		*pi++
		return true
	case '[':
		// Find the class body [i, j) and the ']' terminator; an unclosed '[' is a
		// literal '[' (CPython fnmatch.translate behavior).
		i := *pi + 1
		if i < len(pat) && pat[i] == '!' {
			i++
		}
		if i < len(pat) && pat[i] == ']' {
			i++
		}
		j := i
		for j < len(pat) && pat[j] != ']' {
			j++
		}
		if j >= len(pat) {
			*pi++
			return c == ch // literal '['
		}
		ok := matchGlobClass(pat[*pi+1:j], ch)
		*pi = j + 1
		return ok
	default:
		*pi++
		return c == ch
	}
}

// matchGlobClass interprets a character-class body (between '[' and ']', a leading
// '!' negating) against ch, honoring 'a-z' ranges. A '-' with no following member
// is a literal.
func matchGlobClass(class []rune, ch rune) bool {
	negate := false
	if len(class) > 0 && class[0] == '!' {
		negate = true
		class = class[1:]
	}
	matched := false
	for k := 0; k < len(class); {
		if k+2 < len(class) && class[k+1] == '-' {
			if class[k] <= ch && ch <= class[k+2] {
				matched = true
			}
			k += 3
		} else {
			if class[k] == ch {
				matched = true
			}
			k++
		}
	}
	return matched != negate
}
