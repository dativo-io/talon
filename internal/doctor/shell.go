package doctor

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// shellWord renders a configured value as one POSIX shell word for a
// copy-paste remediation command, so the value never becomes shell syntax:
// agent.key.secret_name and a provider's secret_name accept any non-empty
// string. A value made only of characters no shell treats specially is
// printed as it is; anything else is single-quoted, an embedded ' written as
// '\”. ok is false for a value with a control or format character (an escape
// sequence, a newline, a bidi override): printed raw it would also reach the
// terminal, so the caller prints no command for it (unprintableNameFix).
func shellWord(s string) (word string, ok bool) {
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsGraphic(r) }) >= 0 {
		return "", false
	}
	if s != "" && strings.IndexFunc(s, func(r rune) bool { return !shellPlain(r) }) < 0 {
		return s, true
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'", true
}

// printable escapes every control or format character of s as %q would (an
// escape sequence, a newline, a bidi override): no configured name, and no
// error text that quotes one, reaches the operator's terminal raw.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsGraphic(r) {
			b.WriteRune(r)
			continue
		}
		b.WriteString(strings.Trim(strconv.QuoteRune(r), "'"))
	}
	return b.String()
}

// shellPlain reports a character no POSIX shell treats specially anywhere in
// an argument word.
func shellPlain(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:@%+=,", r)
}

// unprintableNameFix replaces a remediation command whose secret name cannot
// be printed safely; the message beside it shows the name escaped.
const unprintableNameFix = "The configured secret name contains control or format characters (shown escaped above): correct secret_name in the file, then run talon doctor again"

// storeKeyCommand is the copy-paste command that stores a secret from the
// environment variable env (the value on stdin): a use case's key scoped to
// its tenant and agent, a provider key (no agent) unscoped.
func storeKeyCommand(env, name, tenant, agent string) (string, bool) {
	n, ok1 := shellWord(name)
	tn, ok2 := shellWord(tenant)
	ag, ok3 := shellWord(agent)
	if !ok1 || !ok2 || !ok3 {
		return "", false
	}
	cmd := fmt.Sprintf("printf '%%s' \"$%s\" | talon secrets set %s", env, n)
	if agent != "" {
		cmd += " --tenant " + tn + " --agent " + ag
	}
	return cmd, true
}
