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
	out, err := exec.CommandContext(t.Context(), "git", "-C", "..", "ls-files", "-s", "-z").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	for _, row := range strings.Split(string(out), "\x00") {
		if row == "" {
			continue
		}
		meta, name, _ := strings.Cut(row, "\t")
		if p := trackedPathProblem(name); p != "" {
			t.Error(p)
		}
		fields := strings.Fields(meta)
		if len(fields) != 3 || fields[0] != "120000" {
			continue
		}
		target, err := exec.CommandContext(t.Context(), "git", "-C", "..", "cat-file", "blob", fields[1]).Output()
		if err != nil {
			t.Fatalf("%s: reading the link target: %v", name, err)
		}
		if p := symlinkProblem(name, string(target)); p != "" {
			t.Error(p)
		}
	}
}

// The two rules, on the shapes that must be caught and the ones that must
// not: the original defect (an absolute link named node_modules), a relative
// link that climbs out of the repository, and legitimate in-repository links.
func TestTrackedSymlinks_Rules(t *testing.T) {
	for _, c := range []struct {
		name, target string
		bad          bool
	}{
		{"tests/browser/node_modules", "/home/dev/src/talon/tests/browser/node_modules", true},
		{"docs/link", "/etc/passwd", true},
		{"docs/link", "../../outside", true},
		{"a/b/link", "../../../x", true},
		{"link", "..", true},
		{"docs/link", "../README.md", false},
		{"a/b/link", "../c/file", false},
		{"link", "docs/guides", false},
	} {
		got := symlinkProblem(c.name, c.target)
		if (got != "") != c.bad {
			t.Errorf("symlinkProblem(%q → %q) = %q, want bad=%v", c.name, c.target, got, c.bad)
		}
	}
	for _, c := range []struct {
		name string
		bad  bool
	}{
		{"internal/console/frontend/node_modules", true},
		{"tests/browser/node_modules/@playwright/test/package.json", true},
		{"node_modules", true},
		{"docs/node_modules.md", false},
		{"internal/console/frontend/package-lock.json", false},
	} {
		if got := trackedPathProblem(c.name); (got != "") != c.bad {
			t.Errorf("trackedPathProblem(%q) = %q, want bad=%v", c.name, got, c.bad)
		}
	}
}

// trackedPathProblem rejects installed dependencies anywhere in the index.
func trackedPathProblem(name string) string {
	for _, part := range strings.Split(name, "/") {
		if part == "node_modules" {
			return name + ": installed dependencies are tracked; they come from the lockfile (npm ci)"
		}
	}
	return ""
}

// symlinkProblem rejects a link whose target is absolute or resolves
// outside the repository.
func symlinkProblem(name, target string) string {
	resolved := path.Clean(path.Join(path.Dir(name), target))
	if path.IsAbs(target) || resolved == ".." || strings.HasPrefix(resolved, "../") {
		return name + " → " + target + ": a tracked symlink must resolve inside the repository"
	}
	return ""
}
