//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/effective"
)

// onboardingGuide is the guide whose marked steps this acceptance executes.
var onboardingGuide = filepath.Join("..", "..", "docs", "guides", "add-talon-to-existing-app.md")

// documentedStepRe matches a fenced block of the guide that carries an
// acceptance marker: the block is executed as written, so a guide that
// drifts from the product fails here.
var documentedStepRe = regexp.MustCompile("(?s)<!-- onboarding-acceptance: ([a-z-]+) -->\n```[a-z]*\n(.*?)\n```")

func documentedSteps(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(onboardingGuide)
	if err != nil {
		t.Fatalf("reading the onboarding guide: %v", err)
	}
	steps := map[string]string{}
	for _, m := range documentedStepRe.FindAllStringSubmatch(string(raw), -1) {
		if _, dup := steps[m[1]]; dup {
			t.Fatalf("the guide marks step %q twice", m[1])
		}
		steps[m[1]] = m[2]
	}
	for _, name := range []string{"keys", "load", "config", "provider-key", "register", "register-output", "start", "check"} {
		if strings.TrimSpace(steps[name]) == "" {
			t.Fatalf("the guide has no block marked <!-- onboarding-acceptance: %s -->", name)
		}
	}
	return steps
}

// documentedInstall is an engineer's shell following the guide: an empty
// directory, `talon` on PATH, and nothing of Talon in the environment. Every
// credential the processes see comes from the file the guide creates.
type documentedInstall struct {
	t     *testing.T
	dir   string
	env   []string
	steps map[string]string
}

func (d *documentedInstall) shell(script string) *exec.Cmd {
	cmd := exec.Command("bash", "-c", "set -eu\n"+script)
	cmd.Dir = d.dir
	cmd.Env = d.env
	return cmd
}

// run executes a documented block in a new shell. The guide says to load
// talon.env in every new shell first, so every step after `keys` does.
func (d *documentedInstall) run(step, script string) string {
	d.t.Helper()
	if step != "keys" {
		script = d.steps["load"] + "\n" + script
	}
	out, err := d.shell(script).CombinedOutput()
	if err != nil {
		d.t.Fatalf("documented step %q failed: %v\n%s", step, err, out)
	}
	return string(out)
}

// keys reads talon.env as the shell does: NAME=value lines.
func (d *documentedInstall) keys() map[string]string {
	d.t.Helper()
	raw, err := os.ReadFile(filepath.Join(d.dir, "talon.env"))
	if err != nil {
		d.t.Fatalf("the documented key step wrote no talon.env: %v", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			d.t.Fatalf("talon.env has a line that is not NAME=value")
		}
		out[name] = value
	}
	return out
}

// listenAddresses returns the local addresses of the sockets listening on
// port. On Linux this is the kernel's socket table, so a wildcard bind
// cannot be missed; elsewhere it is every address of this host that accepts
// a connection on the port.
func listenAddresses(t *testing.T, port int) []string {
	t.Helper()
	if runtime.GOOS != "linux" {
		return dialableAddresses(t, port)
	}
	var out []string
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(table)
		if err != nil {
			if table == "/proc/net/tcp6" && os.IsNotExist(err) {
				continue
			}
			t.Fatalf("reading the socket table: %v", err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[3] != "0A" { // 0A = LISTEN
				continue
			}
			addr, hexPort, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			var p int
			if _, err := fmt.Sscanf(hexPort, "%x", &p); err == nil && p == port {
				out = append(out, addr)
			}
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			t.Fatalf("reading %s: %v", table, err)
		}
	}
	return out
}

func dialableAddresses(t *testing.T, port int) []string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("listing this host's addresses: %v", err)
	}
	var out []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ipn.IP.String(), fmt.Sprint(port)), time.Second)
		if err != nil {
			continue
		}
		_ = c.Close()
		if ipn.IP.IsLoopback() {
			out = append(out, loopbackOnly)
		} else {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

// loopbackOnly is 127.0.0.1 as the kernel's socket table prints it.
const loopbackOnly = "0100007F"

// adminStatus calls an administrative route and returns the HTTP status.
// header and value name the credential, when there is one.
func adminStatus(t *testing.T, method, url, header, value string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if header != "" {
		req.Header.Set(header, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestE2E_Onboarding_DocumentedSecureStartup executes the guide's own
// commands (#472, #567 review): the keys go into a file only the operator
// can read, the server starts with the admin key and on loopback only, and
// the three credentials stay apart. It proves that an administrative route
// refuses a request with no credential and one with the application's key,
// that the application's key still does its own job, and that the provider
// was reached exactly as often as an authorized request was sent.
//
// The last part is the control: the same installation started WITHOUT an
// admin key keeps the existing development-mode semantics.
func TestE2E_Onboarding_DocumentedSecureStartup(t *testing.T) {
	for _, tool := range []string{"bash", "openssl", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("the documented steps need %s: %v", tool, err)
		}
	}
	steps := documentedSteps(t)

	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl_onboarding","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`))
	}))
	t.Cleanup(upstream.Close)

	root := t.TempDir()
	d := &documentedInstall{t: t, dir: filepath.Join(root, "installation"), steps: steps}
	bin, home := filepath.Join(root, "bin"), filepath.Join(root, "home")
	for _, p := range []string{d.dir, bin, home} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(binaryPath, filepath.Join(bin, "talon")); err != nil {
		t.Fatal(err)
	}
	// No TALON_* variable is inherited: what the processes know comes from
	// the documented file. The data directory is the default, under HOME.
	d.env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + home, "OPENAI_API_KEY=" + onboardingProviderKey}
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		d.env = append(d.env, "TMPDIR="+tmp)
	}

	ph := newOnboardingPhases(t, "documented installation (guide 1-3)")

	// --- Keys: generated into a file only the operator can read. ---------
	ph.step("secure configuration", func() { d.run("keys", steps["keys"]) })
	info, err := os.Stat(filepath.Join(d.dir, "talon.env"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("talon.env has mode %o, want 0600: other users of the host could read the operator's keys", mode)
	}
	keys := d.keys()
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, name := range []string{"TALON_SECRETS_KEY", "TALON_SIGNING_KEY", "TALON_ADMIN_KEY"} {
		if !hex64.MatchString(keys[name]) {
			t.Fatalf("talon.env does not hold a generated 256-bit %s", name)
		}
	}
	if len(keys) != 3 || keys["TALON_SECRETS_KEY"] == keys["TALON_SIGNING_KEY"] || keys["TALON_SIGNING_KEY"] == keys["TALON_ADMIN_KEY"] || keys["TALON_SECRETS_KEY"] == keys["TALON_ADMIN_KEY"] {
		t.Fatalf("talon.env must hold exactly three different keys, has %d entries", len(keys))
	}
	adminKey := keys["TALON_ADMIN_KEY"]

	// --- Installation, provider key, registration: as documented. --------
	if strings.Count(steps["config"], "https://api.openai.com") != 1 {
		t.Fatal("the documented configuration no longer names the provider's base URL once")
	}
	cfg := strings.Replace(steps["config"], "https://api.openai.com", upstream.URL, 1)
	ph.step("secure configuration", func() {
		if err := os.WriteFile(filepath.Join(d.dir, "talon.config.yaml"), []byte(cfg+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		d.run("provider-key", steps["provider-key"])
	})
	var out string
	ph.step("registration", func() { out = d.run("register", steps["register"]) })
	secretAt := strings.Index(out, "SECRET — shown once")
	if secretAt < 0 {
		t.Fatalf("the documented registration printed no secret block:\n%s", out)
	}
	appKey := useCaseKeyRe.FindString(out[secretAt:])
	if appKey == "" {
		t.Fatalf("the documented registration printed no Talon key:\n%s", out)
	}
	// The output the guide shows is the output the command prints. What
	// differs from run to run is compared as a placeholder: generated ids,
	// the key, and the server address (it depends on what answers at the
	// default port of this host).
	variable := regexp.MustCompile(`al_[0-9a-f-]+|talon_uc_\S+|Base URL .*`)
	normalize := func(text string) string { return variable.ReplaceAllString(text, "…") }
	printed := normalize(out)
	for _, line := range strings.Split(normalize(steps["register-output"]), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.Contains(printed, line) {
			t.Fatalf("the guide shows a registration output line the command does not print: %q\nprinted:\n%s", line, out)
		}
	}
	if _, err := os.Stat(filepath.Join(d.dir, "agents", "customer-support", "agent.talon.yaml")); err != nil {
		t.Fatalf("the documented registration wrote no agent file: %v", err)
	}

	// --- Start: the documented command, on the documented address. -------
	if !strings.Contains(steps["start"], "--host 127.0.0.1") || strings.Count(steps["start"], "8080") != 1 || strings.Contains(strings.TrimSpace(steps["start"]), "\n") {
		t.Fatalf("the documented start command must be one line that binds 127.0.0.1 and names port 8080 once:\n%s", steps["start"])
	}
	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	withPort := func(s string) string { return strings.ReplaceAll(s, "8080", fmt.Sprint(port)) }
	serve := func(command string) (stop func(), pid int) {
		t.Helper()
		// exec: the shell that loaded talon.env becomes the server, as when
		// an operator types the command.
		cmd := d.shell(steps["load"] + "\nexec " + command)
		logFile, err := os.OpenFile(filepath.Join(d.dir, "serve.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = logFile, logFile
		if err := cmd.Start(); err != nil {
			t.Fatalf("starting the server: %v", err)
		}
		stopped := false
		stop = func() {
			if stopped {
				return
			}
			stopped = true
			_ = cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
			_ = logFile.Close()
		}
		t.Cleanup(stop)
		deadline := time.Now().Add(25 * time.Second)
		for {
			resp, err := http.Get(base + "/health")
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return stop, cmd.Process.Pid
				}
			}
			if time.Now().After(deadline) {
				logged, _ := os.ReadFile(filepath.Join(d.dir, "serve.log"))
				t.Fatalf("the server did not become healthy:\n%s", tail(string(logged), 3000))
			}
			time.Sleep(150 * time.Millisecond)
		}
	}
	var (
		stop func()
		pid  int
	)
	ph.step("startup and admin check", func() { stop, pid = serve(withPort(strings.TrimSpace(steps["start"]))) })

	if got := listenAddresses(t, port); len(got) != 1 || got[0] != loopbackOnly {
		t.Fatalf("the documented start must listen on 127.0.0.1 only, the listening sockets on port %d are %v", port, got)
	}
	// No key is a process argument: `ps` on the host shows the command line.
	if runtime.GOOS == "linux" {
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil || len(cmdline) == 0 {
			t.Fatalf("reading the server's command line: %v", err)
		}
		for name, value := range keys {
			if bytes.Contains(cmdline, []byte(value)) {
				t.Fatalf("%s is visible in the server's process arguments", name)
			}
		}
	}

	// --- The documented check: 401 without a credential, 200 as operator.
	var checked string
	ph.step("startup and admin check", func() { checked = d.run("check", withPort(steps["check"])) })
	if got := strings.Fields(checked); len(got) != 2 || got[0] != "401" || got[1] != "200" {
		t.Fatalf("the documented check must print 401 then 200, printed %v", got)
	}

	// --- The three credentials stay apart. --------------------------------
	admin := []struct{ method, path string }{
		{http.MethodGet, "/v1/secrets"},
		{http.MethodGet, "/v1/secrets/audit"},
		{http.MethodGet, "/v1/policies"},
		{http.MethodGet, "/v1/agents/fleet"},
		{http.MethodGet, "/api/v1/metrics"},
	}
	for _, r := range admin {
		for _, c := range []struct{ who, header, value string }{
			{"no credential", "", ""},
			{"the application's key as a bearer token", "Authorization", "Bearer " + appKey},
			{"the application's key in the admin header", "X-Talon-Admin-Key", appKey},
			{"the provider's key", "X-Talon-Admin-Key", onboardingProviderKey},
			{"a wrong admin key", "X-Talon-Admin-Key", strings.Repeat("0", 64)},
		} {
			if st := adminStatus(t, r.method, base+r.path, c.header, c.value); st != http.StatusUnauthorized {
				t.Errorf("%s %s with %s: HTTP %d, want 401", r.method, r.path, c.who, st)
			}
		}
		if st := adminStatus(t, r.method, base+r.path, "X-Talon-Admin-Key", adminKey); st != http.StatusOK {
			t.Errorf("%s %s with the operator's admin key: HTTP %d, want 200", r.method, r.path, st)
		}
	}
	// A state-changing administrative request with the application's key
	// is refused, and it changed nothing: the application is still served.
	lockdown := base + "/v1/overrides/default/lockdown"
	for _, c := range []struct{ header, value string }{{"", ""}, {"Authorization", "Bearer " + appKey}, {"X-Talon-Admin-Key", appKey}} {
		if st := adminStatus(t, http.MethodPost, lockdown, c.header, c.value); st != http.StatusUnauthorized {
			t.Fatalf("POST /v1/overrides/default/lockdown without the operator's key (%q): HTTP %d, want 401", c.header, st)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	// --- The application's key does the application's job. ----------------
	if n := calls.Load(); n != 0 {
		t.Fatalf("the provider was called %d times before the application sent anything", n)
	}
	var st int
	ph.step("first governed request", func() { st = chatThroughGateway(t, base, appKey, "") })
	if st != http.StatusOK {
		t.Fatalf("the application's request with its Talon key: HTTP %d, want 200", st)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("one authorized request must reach the provider once, it was called %d times", n)
	}
	// The operator's key is not an application credential, and no key is none.
	for who, key := range map[string]string{"the admin key": adminKey, "an unknown key": "talon_uc_" + strings.Repeat("0", 48)} {
		if st := chatThroughGateway(t, base, key, ""); st != http.StatusUnauthorized {
			t.Fatalf("a gateway request with %s: HTTP %d, want 401", who, st)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("a refused request reached the provider: %d calls, want 1", n)
	}

	// The documented verification reads the request as this use case's, with
	// the credential stored now.
	var report effective.Report
	var verified string
	ph.step("verification", func() { verified = d.run("verify", "talon agents show customer-support --effective --json") })
	if err := json.Unmarshal([]byte(verified), &report); err != nil {
		t.Fatalf("decoding the effective report: %v", err)
	}
	if report.Verification == nil || report.Verification.Reading.Code != effective.ReadingTrafficMatches {
		t.Fatalf("after one authorized request the documented path must verify, got %+v", report.Verification)
	}

	// --- Nothing but talon.env holds the operator's keys in clear text. ---
	stop()
	err = filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
		if err != nil || !e.Type().IsRegular() || path == filepath.Join(d.dir, "talon.env") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for name, value := range keys {
			if bytes.Contains(raw, []byte(value)) {
				t.Errorf("%s is in clear text in %s", name, strings.TrimPrefix(path, root))
			}
		}
		if bytes.Contains(raw, []byte(appKey)) || bytes.Contains(raw, []byte(onboardingProviderKey)) {
			t.Errorf("an application or provider key is in clear text in %s", strings.TrimPrefix(path, root))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading the installation's files: %v", err)
	}

	// --- Control: development mode is what it was. ------------------------
	// The same installation, started without an admin key (still on
	// loopback): administrative routes accept a request with no credential,
	// and the application's key keeps working. Nothing in this change made
	// development mode stricter or looser.
	devStop, _ := serve("env -u TALON_ADMIN_KEY " + withPort(strings.TrimSpace(steps["start"])))
	defer devStop()
	if got := listenAddresses(t, port); len(got) != 1 || got[0] != loopbackOnly {
		t.Fatalf("the control server must listen on 127.0.0.1 only, got %v", got)
	}
	if st := adminStatus(t, http.MethodGet, base+"/v1/secrets", "", ""); st != http.StatusOK {
		t.Fatalf("development mode (no admin key): GET /v1/secrets without a credential is HTTP %d, want 200 (unchanged semantics)", st)
	}
	if st := chatThroughGateway(t, base, appKey, ""); st != http.StatusOK {
		t.Fatalf("development mode: the application's request is HTTP %d, want 200", st)
	}
	if st := chatThroughGateway(t, base, "talon_uc_"+strings.Repeat("0", 48), ""); st != http.StatusUnauthorized {
		t.Fatalf("development mode: an unknown key on the gateway is HTTP %d, want 401", st)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("the provider was called %d times, want 2 (one authorized request per server)", n)
	}
}
