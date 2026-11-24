//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #575: an engineer connecting two existing applications to one Talon
// installation (the add-talon-to-existing-app guide: one company policy,
// `talon agents add` twice) meets three failures first — a config file that
// cannot be used, a key or provider secret that does not resolve, and an
// endpoint that cannot be reached. `talon doctor` on the built (or released,
// TALON_E2E_BINARY) binary must name each accurately, per use case, without
// printing a key and without changing a byte of the stores.

type doctorReport struct {
	Status string `json:"status"`
	Checks []struct {
		Name    string `json:"name"`
		Status  string `json:"status"`
		Message string `json:"message"`
		Fix     string `json:"fix"`
	} `json:"checks"`
}

func runDoctor(t *testing.T, dir string, env map[string]string) (doctorReport, string) {
	t.Helper()
	out, stderr, _ := RunTalon(t, dir, env, "doctor", "--format", "json")
	var r doctorReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("doctor --format json: %v\n%s\n%s", err, out, stderr)
	}
	return r, out + stderr
}

func (r doctorReport) check(name string) (status, message, fix string, ok bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status, c.Message, c.Fix, true
		}
	}
	return "", "", "", false
}

// storeDigest is the installation's whole tree: every path, type, mode,
// size and content digest. SQLite's own sidecar files of a WAL-mode store
// are left out — the -shm index (created by any connection, read-only
// included) and an EMPTY -wal (removed when the last connection closes);
// neither holds data.
func storeDigest(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			fmt.Fprintf(&b, "%s link %s\n", rel, target)
		case fi.IsDir():
			fmt.Fprintf(&b, "%s dir %s\n", rel, fi.Mode())
		case strings.HasSuffix(p, "-shm") || (strings.HasSuffix(p, "-wal") && fi.Size() == 0):
		default:
			data, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			sum := sha256.Sum256(data)
			fmt.Fprintf(&b, "%s file %s %s\n", rel, fi.Mode(), hex.EncodeToString(sum[:8]))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A fresh directory: doctor reports what talon would create and creates
// nothing (PR #592 review: no data directory, store, vault or probe file).
func TestE2E_Doctor_FreshInstallationStaysEmpty(t *testing.T) {
	root := t.TempDir()
	before := storeDigest(t, root)
	r, raw := runDoctor(t, root, map[string]string{"TALON_DATA_DIR": filepath.Join(root, "data")})
	if after := storeDigest(t, root); after != before {
		t.Fatalf("doctor created something on a fresh installation:\n%s\n→\n%s", before, after)
	}
	if st, msg, _, _ := r.check("data_dir_writable"); st != "pass" || !strings.Contains(msg, "does not exist yet") {
		t.Fatalf("data_dir_writable: %q %q\n%s", st, msg, raw)
	}
}

func TestE2E_Doctor_OnboardingFailureModes(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer provider.Close()
	dir := t.TempDir()
	cfg := fmt.Sprintf(`agents_dir: ./agents
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "%s"
  organization_policy:
    defaults:
      pii_action: block
      daily_cost: 50
      monthly_cost: 500
    constraints:
      forbidden_tools: ["delete_*"]
`, provider.URL)
	cfgPath := filepath.Join(dir, "talon.config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", "openai-api-key", "sk-provider-e2e-doctor-0000"); code != 0 {
		t.Fatalf("provider secret: %s", stderr)
	}
	var keys []string
	for _, app := range [][]string{{"customer-support", "support-engineering", "AI customer support assistant"}, {"hr-copilot", "people-ops", "HR policy assistant"}} {
		out, stderr, code := RunTalon(t, dir, nil, "agents", "add", app[0], "--owner", app[1], "--description", app[2])
		if code != 0 {
			t.Fatalf("agents add %s: %d\n%s\n%s", app[0], code, out, stderr)
		}
		k := useCaseKeyRe.FindString(out)
		if k == "" {
			t.Fatalf("agents add %s printed no key", app[0])
		}
		keys = append(keys, k)
	}
	noKeys := func(t *testing.T, text string) {
		t.Helper()
		for _, k := range append(keys, "sk-provider-e2e-doctor-0000") {
			if strings.Contains(text, k) {
				t.Fatal("doctor printed a secret value")
			}
		}
	}

	t.Run("healthy: both use cases resolve, nothing changes", func(t *testing.T) {
		before := storeDigest(t, dir)
		r, raw := runDoctor(t, dir, nil)
		noKeys(t, raw)
		for _, name := range []string{"use_case_key:customer-support", "use_case_key:hr-copilot", "secrets_key_decrypts_vault", "gateway_agent_identity", "gateway_secrets_openai", "gateway_upstream_openai"} {
			if st, msg, _, ok := r.check(name); !ok || st != "pass" {
				t.Fatalf("%s: %q %s", name, st, msg)
			}
		}
		if after := storeDigest(t, dir); after != before {
			t.Fatalf("doctor changed the stores: %s → %s", before, after)
		}
	})

	t.Run("unreadable config: the one cause, and serve says it too", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode-000 file")
		}
		if err := os.Chmod(cfgPath, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(cfgPath, 0o600) }()
		r, raw := runDoctor(t, dir, nil)
		noKeys(t, raw)
		st, msg, fix, ok := r.check("config_load")
		if !ok || st != "fail" || !strings.Contains(msg, "permission denied") || !strings.Contains(fix, "readable") {
			t.Fatalf("config_load: %q %q %q", st, msg, fix)
		}
		if _, _, _, ok := r.check("llm_keys"); ok {
			t.Fatal("doctor judged configless defaults while the config file exists")
		}
		port := freePort(t)
		_, stderr, code := RunTalon(t, dir, nil, "serve", "--host", "127.0.0.1", "--port", fmt.Sprint(port))
		if code == 0 || !strings.Contains(stderr, "exists but cannot be used") || !strings.Contains(stderr, "permission denied") {
			t.Fatalf("serve must refuse with the cause: %d %s", code, stderr)
		}
	})

	t.Run("the second use case's key is missing: it alone is named", func(t *testing.T) {
		p := filepath.Join(dir, "agents", "hr-copilot", "agent.talon.yaml")
		orig, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.WriteFile(p, orig, 0o600) }()
		if err := os.WriteFile(p, []byte(strings.Replace(string(orig), "hr-copilot-talon-key", "hr-copilot-key-typo", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		r, raw := runDoctor(t, dir, nil)
		noKeys(t, raw)
		if st, _, _, _ := r.check("use_case_key:customer-support"); st != "pass" {
			t.Fatalf("the first use case is unaffected: %q", st)
		}
		st, msg, fix, _ := r.check("use_case_key:hr-copilot")
		if st != "fail" || !strings.Contains(msg, "not in the vault") || !strings.Contains(fix, "--agent hr-copilot") {
			t.Fatalf("hr-copilot: %q %q %q", st, msg, fix)
		}
	})

	t.Run("a different TALON_SECRETS_KEY: undecryptable, never 'set it again'", func(t *testing.T) {
		before := storeDigest(t, dir)
		r, raw := runDoctor(t, dir, map[string]string{"TALON_SECRETS_KEY": strings.Repeat("x", 32)})
		noKeys(t, raw)
		if st, msg, fix, _ := r.check("secrets_key_decrypts_vault"); st != "fail" || !strings.Contains(msg, "decrypts none") || !strings.Contains(fix, "Restore") {
			t.Fatalf("vault key: %q %q %q", st, msg, fix)
		}
		for _, name := range []string{"use_case_key:customer-support", "use_case_key:hr-copilot", "gateway_secrets_openai"} {
			st, msg, fix, _ := r.check(name)
			if st != "fail" || !strings.Contains(msg, "cannot be decrypted") || !strings.Contains(fix, "do not re-set") {
				t.Fatalf("%s: %q %q %q", name, st, msg, fix)
			}
		}
		if after := storeDigest(t, dir); after != before {
			t.Fatalf("doctor changed the stores: %s → %s", before, after)
		}
	})

	t.Run("the provider endpoint is unreachable", func(t *testing.T) {
		provider.Close()
		time.Sleep(50 * time.Millisecond)
		r, raw := runDoctor(t, dir, nil)
		noKeys(t, raw)
		if st, msg, _, _ := r.check("gateway_upstream_openai"); st != "fail" || !strings.Contains(msg, "connection refused") {
			t.Fatalf("upstream: %q %q", st, msg)
		}
	})
}
