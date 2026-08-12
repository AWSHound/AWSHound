package collect

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// bloodhoundCollectKey is the opt-in flag a profile sets in the AWS config file
// to be picked up by `collect`/`all --aws-config`. The AWS SDK ignores unknown
// keys like this, so it is harmless in a normal config.
const bloodhoundCollectKey = "bloodhound_collect"

// ProfilesToCollect parses an AWS config file and returns, in file order, the
// profile names of every section whose body contains `bloodhound_collect = true`.
// Section names follow AWS config-file conventions: "[default]" yields "default"
// and "[profile NAME]" yields "NAME" (a bare "[NAME]", credentials-file style, is
// accepted too). This lets a caller mark which accounts to collect in the config
// itself and point the tool at the file instead of listing --profile flags.
func ProfilesToCollect(configFile string) ([]string, error) {
	f, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("collect: open aws config %q: %w", configFile, err)
	}
	defer f.Close()

	var (
		profiles []string
		section  string // current profile name ("" before the first header)
		collect  bool   // whether the current section opted in
	)
	flush := func() {
		if section != "" && collect {
			profiles = append(profiles, section)
		}
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush() // close out the previous section
			section = parseSectionName(line)
			collect = false
			continue
		}
		if key, val, ok := strings.Cut(line, "="); ok &&
			strings.EqualFold(strings.TrimSpace(key), bloodhoundCollectKey) &&
			isTrue(strings.TrimSpace(val)) {
			collect = true
		}
	}
	flush() // close out the final section
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("collect: read aws config %q: %w", configFile, err)
	}
	return profiles, nil
}

// parseSectionName maps a "[...]" header to the profile name the AWS SDK expects:
// "[default]" -> "default", "[profile NAME]" -> "NAME", "[NAME]" -> "NAME".
func parseSectionName(header string) string {
	inner := strings.TrimSpace(header[1 : len(header)-1])
	if inner == "default" {
		return "default"
	}
	if rest, ok := strings.CutPrefix(inner, "profile "); ok {
		return strings.TrimSpace(rest)
	}
	return inner
}

// isTrue reports whether an AWS config value denotes an enabled boolean.
func isTrue(v string) bool {
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}
