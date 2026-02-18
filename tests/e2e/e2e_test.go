//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "talon-e2e-build-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e TestMain: mkdir temp: %v\n", err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(dir, "talon")
	cmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/talon")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e TestMain: build: %v\n%s\n", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// RunTalon runs the talon binary with the given args. dataDir is used as TALON_DATA_DIR;
// env can add or override env vars (e.g. OPENAI_API_KEY, OPENAI_BASE_URL).
// Returns stdout, stderr, and the exit code (or -1 if the process failed to start).
func RunTalon(t *testing.T, dataDir string, env map[string]string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "TALON_DATA_DIR="+dataDir)
	cmd.Env = append(cmd.Env, "TALON_SECRETS_KEY="+testSecretsKey)
	cmd.Env = append(cmd.Env, "TALON_SIGNING_KEY="+testSigningKey)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Dir = dataDir
	var outBuf, errBuf buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return string(outBuf.b), string(errBuf.b), exitCode
}

type buffer struct {
	b []byte
}

func (b *buffer) Write(p []byte) (n int, err error) {
	b.b = append(b.b, p...)
	return len(p), nil
}

// Test keys for e2e (32 bytes). Must match internal/testutil for consistency.
const (
	testSecretsKey = "12345678901234567890123456789012"
	testSigningKey = "test-signing-key-1234567890123456"
)
