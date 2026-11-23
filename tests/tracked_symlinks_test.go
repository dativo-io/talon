package tests

import (
	"os/exec"
	"path"
	"strings"
	"testing"
)

// TestTrackedSymlinks_StayInsideTheRepository: a symbolic link committed to
// the repository must resolve inside it. A link to an absolute path — a
// developer's node_modules, committed by accident in #431 — is recreated by
// git in every other checkout pointing at a path that does not exist there,
// or at itself (the link `tests/browser/node_modules` →
// `/home/…/tests/browser/node_modules` loops in the checkout it names),
// which breaks `npm`, Playwright and the screenshot baseline locally.
// Installed dependencies are never tracked at all.
func TestTrackedSymlinks_StayInsideTheRepository(t *testing.T) {
	out, err := exec.Command("git", "-C", "..", "ls-files", "-s", "-z").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	for _, row := range strings.Split(string(out), "\x00") {
		if row == "" {
			continue
		}
		meta, name, _ := strings.Cut(row, "\t")
		for _, part := range strings.Split(name, "/") {
			if part == "node_modules" {
				t.Errorf("%s: installed dependencies are tracked; they come from the lockfile (npm ci)", name)
			}
		}
		fields := strings.Fields(meta)
		if len(fields) != 3 || fields[0] != "120000" {
			continue
		}
		target, err := exec.Command("git", "-C", "..", "cat-file", "blob", fields[1]).Output()
		if err != nil {
			t.Fatalf("%s: reading the link target: %v", name, err)
		}
		dest := string(target)
		resolved := path.Clean(path.Join(path.Dir(name), dest))
		if path.IsAbs(dest) || resolved == ".." || strings.HasPrefix(resolved, "../") {
			t.Errorf("%s → %s: a tracked symlink must resolve inside the repository", name, dest)
		}
	}
}
