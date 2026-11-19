package tests

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestGoToolchain_GoModIsTheOnlyVersion: go.mod names the Go version Talon is
// built with (#572). Workflows read it from there; the places that cannot
// (Dockerfile FROM lines, the nested agent module, the screenshot workflow,
// whose text is a render input) must name the same version, so a security
// bump that misses one fails here instead of shipping an executable built by
// another compiler. The goreleaser-cross image is the one deliberate
// exception: its tag is a build environment, the compiler comes from go.mod
// (scripts/release-build.sh) and is read back from every released
// executable (scripts/release-toolchain-check.sh).
func TestGoToolchain_GoModIsTheOnlyVersion(t *testing.T) {
	want := goModVersion(t)

	for rel, pattern := range map[string]string{
		"examples/openshell/agent/go.mod":           `(?m)^go (\S+)$`,
		"Dockerfile":                                `(?m)^FROM golang:(\S+?)-alpine`,
		"examples/openshell/agent/Dockerfile":       `(?m)^FROM golang:(\S+?)-alpine`,
		".github/workflows/console-screenshots.yml": `go-version: '([^']+)'`,
		"CONTRIBUTING.md":                           `Install Go (\d+\.\d+\.\d+)\+`,
	} {
		got := regexp.MustCompile(pattern).FindStringSubmatch(readRepoFile(t, rel))
		if got == nil {
			t.Errorf("%s: no Go version found (pattern %s); update this test if the file changed shape", rel, pattern)
			continue
		}
		if got[1] != want {
			t.Errorf("%s names Go %s, go.mod names %s", rel, got[1], want)
		}
	}

	// Every other workflow takes the version from go.mod.
	workflows, err := filepath.Glob(filepath.Join("..", ".github", "workflows", "*.yml"))
	if err != nil || len(workflows) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	literal := regexp.MustCompile(`(?m)^\s*go-version:|golang:\d`)
	for _, wf := range workflows {
		if filepath.Base(wf) == "console-screenshots.yml" {
			continue
		}
		b, err := os.ReadFile(wf)
		if err != nil {
			t.Fatal(err)
		}
		if loc := literal.Find(b); loc != nil {
			t.Errorf("%s pins a Go version literally (%q); use go-version-file: go.mod", filepath.Base(wf), strings.TrimSpace(string(loc)))
		}
	}
}

// TestGoToolchain_ReleaseBuildUsesGoModAndIsVerified: the release build is
// one command shared with its snapshot rehearsal, takes the compiler from
// go.mod, and the release workflow reads it back from the artifacts.
func TestGoToolchain_ReleaseBuildUsesGoModAndIsVerified(t *testing.T) {
	want := goModVersion(t)
	// The release build: one command, toolchain from go.mod, and the build
	// image on the same Go line and not newer than go.mod.
	build := readRepoFile(t, "scripts/release-build.sh")
	if !strings.Contains(build, `-e GOTOOLCHAIN="go$go_version"`) {
		t.Error("scripts/release-build.sh must pass the go.mod toolchain to the build image as GOTOOLCHAIN")
	}
	img := regexp.MustCompile(`goreleaser-cross:v(\d+\.\d+)\.(\d+)"`).FindStringSubmatch(build)
	if img == nil {
		t.Fatal("scripts/release-build.sh must pin the goreleaser-cross image by version")
	}
	if !strings.HasPrefix(want, img[1]+".") {
		t.Errorf("goreleaser-cross image is Go %s.x, go.mod names %s: the build image must be on the same Go line", img[1], want)
	}
	release := readRepoFile(t, ".github/workflows/release.yml")
	if strings.Contains(release, "goreleaser-cross:v") {
		t.Error("release.yml must build through scripts/release-build.sh, not its own docker run of goreleaser-cross")
	}
	for _, need := range []string{"bash scripts/release-build.sh release", "scripts/release-toolchain-check.sh", "steps.cap.outputs.toolchain == 'true'"} {
		if !strings.Contains(release, need) {
			t.Errorf("release.yml: missing %q", need)
		}
	}
	if !strings.Contains(readRepoFile(t, ".github/workflows/release-build-snapshot.yml"), "bash scripts/release-build.sh snapshot") {
		t.Error("the snapshot rehearsal must run the release build command")
	}
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func goModVersion(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^go (\d+\.\d+\.\d+)$`).FindStringSubmatch(readRepoFile(t, "go.mod"))
	if m == nil {
		t.Fatal("go.mod must name a full Go version (go MAJOR.MINOR.PATCH)")
	}
	return m[1]
}
