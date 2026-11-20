//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scripts/quickstart.sh (#463) over the built binary instead of the
// published image (TALON_QUICKSTART_BIN): the same commands, requests and
// checks the Docker path runs — a PII block and a model denial with no
// provider anywhere, an unknown key refused, two evidence records whose
// signatures verify. The Docker path is run by CI on the release image and
// by release.yml / install-smoke.yml on the published one.
func TestE2E_QuickstartScript_LocalBinary(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "quickstart.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(), "TALON_QUICKSTART_BIN="+binaryPath, fmt.Sprintf("TALON_QUICKSTART_PORT=%d", freePort(t)), "TMPDIR="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("quickstart failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"PASS Talon blocked it before any provider call",
		"PASS Talon denied it before any provider call",
		"PASS Talon refused the caller",
		"PASS two evidence records were written",
		"PASS talon quickstart in ",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("quickstart output missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(string(out), "PASS signature verified: gw_"); n != 2 {
		t.Errorf("want 2 verified signatures, got %d:\n%s", n, out)
	}
	if strings.Contains(string(out), "FAIL") {
		t.Errorf("quickstart reported a failure:\n%s", out)
	}
	// The next steps are documents of this repository that exist (#563):
	// the quickstart never points at a guide the release does not ship.
	links := regexp.MustCompile(`https://github\.com/dativo-io/talon/blob/[^/]+/(\S+)`).FindAllStringSubmatch(string(out), -1)
	if len(links) != 2 {
		t.Fatalf("want two next-step links, got %d:\n%s", len(links), out)
	}
	for _, l := range links {
		if _, err := os.Stat(filepath.Join("..", "..", l[1])); err != nil {
			t.Errorf("next-step link %s does not exist in this tree: %v", l[0], err)
		}
	}

	// The advertised command fetches the script from the release tag, the
	// same reference install-smoke.yml executes after publication; a script
	// from main is not a version-pinned installation (#563).
	for _, doc := range []string{script, filepath.Join("..", "..", "docs", "QUICKSTART.md")} {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "https://raw.githubusercontent.com/dativo-io/talon/vX.Y.Z/scripts/quickstart.sh | TALON_VERSION=X.Y.Z bash") {
			t.Errorf("%s does not advertise the release-tag-pinned quickstart command", doc)
		}
		if strings.Contains(string(b), "talon/main/scripts/quickstart.sh") {
			t.Errorf("%s advertises the quickstart script from main", doc)
		}
	}

	// Without a version or image the script refuses instead of assuming latest.
	cmd = exec.Command("bash", script)
	cmd.Env = append(os.Environ(), "TALON_VERSION=", "TALON_IMAGE=", "TALON_QUICKSTART_BIN=")
	out, err = cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "never assumes 'latest'") {
		t.Errorf("the script must refuse without a pinned version: %v\n%s", err, out)
	}
}
