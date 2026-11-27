package doctor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"regexp"
	"sort"
	"syscall"
	"time"

	"github.com/spf13/viper"

	"github.com/dativo-io/talon/internal/action/mcpsource"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

// Onboarding diagnostics (#575): the failures an engineer connecting an
// existing application meets first — a config file that cannot be used, a
// use-case key or provider secret that does not resolve, and an endpoint
// that cannot be reached — each reported accurately, read-only (the vault is
// opened mode=ro; nothing is created, logged or counted) and without ever
// printing a secret value.

// configLoadFailure reports why the infrastructure config cannot be used,
// with the fix for that cause (a permission problem is not a YAML problem).
func configLoadFailure(err error) CheckResult {
	fix := "Check TALON_DATA_DIR and the config file"
	var parse viper.ConfigParseError
	switch {
	case errors.Is(err, fs.ErrPermission):
		fix = "Make talon.config.yaml readable by the user that runs talon (for example: chmod 600 talon.config.yaml as its owner). Talon does not fall back to defaults while the file exists"
	case errors.As(err, &parse):
		fix = "Fix the YAML at the line named above, then run talon doctor again"
	case errors.Is(err, fs.ErrNotExist):
		fix = "The file named with --config does not exist: check the path"
	}
	return CheckResult{
		Name: "config_load", Category: "config", Status: "fail",
		Message: fmt.Sprintf("Cannot load config: %v", err),
		Fix:     fix,
	}
}

// checkVaultKey proves the configured TALON_SECRETS_KEY decrypts the vault:
// "configured" is not "correct". A key that differs from the one the
// secrets were stored with makes every secret look absent elsewhere; the
// fix is to restore the key — re-setting secrets would replace them.
func checkVaultKey(ctx context.Context, cfg *config.Config) CheckResult {
	path := cfg.SecretsDBPath()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return CheckResult{Name: "secrets_key_decrypts_vault", Category: "config", Status: "pass", Message: "no secret stored yet"}
	}
	rep, err := secrets.VerifyFile(ctx, path, cfg.SecretsKey)
	if err != nil {
		return CheckResult{
			Name: "secrets_key_decrypts_vault", Category: "config", Status: "fail",
			Message: fmt.Sprintf("Cannot verify the secrets vault %s: %v", path, err),
			Fix:     "Make the vault readable by the user that runs talon and check TALON_SECRETS_KEY",
		}
	}
	switch n := len(rep.Undecryptable); {
	case rep.Entries == 0:
		return CheckResult{Name: "secrets_key_decrypts_vault", Category: "config", Status: "pass", Message: "no secret stored yet"}
	case n == 0:
		return CheckResult{Name: "secrets_key_decrypts_vault", Category: "config", Status: "pass", Message: fmt.Sprintf("all %d secret(s) decrypt with TALON_SECRETS_KEY", rep.Entries)}
	case n == rep.Entries:
		return CheckResult{
			Name: "secrets_key_decrypts_vault", Category: "config", Status: "fail",
			Message: fmt.Sprintf("TALON_SECRETS_KEY decrypts none of the %d secret(s) in the vault: it is not the key they were stored with", rep.Entries),
			Fix:     restoreKeyFix,
		}
	default:
		return CheckResult{
			Name: "secrets_key_decrypts_vault", Category: "config", Status: "fail",
			Message: fmt.Sprintf("%d of %d secret(s) do not decrypt with TALON_SECRETS_KEY (stored under another key, or damaged): %q", n, rep.Entries, rep.Undecryptable),
			Fix:     restoreKeyFix,
		}
	}
}

// restoreKeyFix is the one fix for a secret that exists but does not decrypt,
// on every line that reports it: setting it again would replace it.
const restoreKeyFix = "Restore the TALON_SECRETS_KEY the secret was stored with (talon.env or the service environment); do not re-set the secret: that replaces it. If the key is right, the entry is damaged: restore the vault from a backup"

// secretProblem explains why a secret does not resolve for tenant/agent
// and how to fix that cause — never by printing a value, and never advising
// a re-set for a secret that exists but does not decrypt.
func secretProblem(err error, name, tenantID, agentID string) (msg, fix string) {
	setCmd, printable := storeKeyCommand("VALUE", name, tenantID, agentID)
	store := func(lead string) string {
		if !printable {
			return unprintableNameFix
		}
		return lead + setCmd
	}
	switch {
	case errors.Is(err, secrets.ErrVaultAbsent):
		return fmt.Sprintf("secret %q is not stored: no secrets vault exists yet", name), store("Store it: ")
	case errors.Is(err, secrets.ErrSecretNotFound):
		return fmt.Sprintf("secret %q is not in the vault", name), store("Store it (or correct the name in the file): ")
	case errors.Is(err, secrets.ErrSecretAccessDenied):
		return fmt.Sprintf("secret %q exists but its ACL does not allow tenant %q, agent %q", name, tenantID, agentID),
			"Review the stored secret ACL and the intended tenant/use-case binding. Have an authorized operator correct the ACL or binding; do not re-set the secret to bypass an access denial: setting it again replaces both its value and its ACL"
	case errors.Is(err, secrets.ErrSecretUndecryptable):
		return fmt.Sprintf("secret %q exists but cannot be decrypted with TALON_SECRETS_KEY (it was stored under another key, or the entry is damaged)", name),
			restoreKeyFix
	default:
		return fmt.Sprintf("secret %q cannot be read: %v", name, err), "Check the vault file and TALON_SECRETS_KEY"
	}
}

// useCases returns the AI use cases serve would load: the fleet under
// agents_dir, or the single default policy.
func useCases(ctx context.Context, cfg *config.Config) ([]agentcatalog.CatalogAgent, error) {
	if cfg.AgentsDir != "" {
		scan, err := agentcatalog.DiscoverAgents(ctx, cfg.AgentsDir)
		if err != nil {
			return nil, err
		}
		return scan.Agents, nil
	}
	pol, err := policy.LoadPolicy(ctx, cfg.DefaultPolicy, false, ".")
	if err != nil {
		return nil, nil //nolint:nilerr // no single policy file is a configless installation; policy_valid reports it
	}
	return []agentcatalog.CatalogAgent{{Name: pol.Agent.Name, TenantID: pol.Agent.TenantID, Path: cfg.DefaultPolicy, Policy: pol}}, nil
}

func tenantOf(t string) string {
	if t == "" {
		return "default"
	}
	return t
}

// checkUseCaseKeys reports, per AI use case, whether its active key resolves
// — so with two applications the one that cannot authenticate is named, and
// a problem with the first never hides the second.
func checkUseCaseKeys(ctx context.Context, cfg *config.Config) []CheckResult {
	agents, err := useCases(ctx, cfg)
	if err != nil || len(agents) == 0 {
		return nil // the identity / policy checks report an unreadable fleet
	}
	vault, vaultErr := secrets.OpenReadOnly(cfg.SecretsDBPath(), cfg.SecretsKey)
	if vault != nil {
		defer vault.Close()
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })
	out := make([]CheckResult, 0, len(agents))
	for _, a := range agents {
		name := "use_case_key:" + a.Name
		if a.Policy == nil || a.Policy.Agent.Key == nil || a.Policy.Agent.Key.SecretName == "" {
			// talon run needs no key; connecting an application does (the
			// gateway identity preflight fails it when a gateway is served).
			out = append(out, CheckResult{
				Name: name, Category: "use_cases", Status: "warn",
				Message: fmt.Sprintf("%s (%s) has no key binding: no application can connect as it through the gateway or /mcp (talon run does not need one)", a.Name, a.Path),
				Fix:     "To connect an application, register it with talon agents add (it writes agent.key.secret_name and mints the key)",
			})
			continue
		}
		secretName, tenant := a.Policy.Agent.Key.SecretName, tenantOf(a.TenantID)
		var getErr error
		var empty bool
		switch vault {
		case nil:
			getErr = vaultErr
		default:
			s, err := vault.Get(ctx, secretName, tenant, a.Name)
			getErr = err
			empty = err == nil && len(s.Value) == 0
		}
		switch {
		case getErr != nil:
			msg, fix := secretProblem(getErr, secretName, tenant, a.Name)
			out = append(out, CheckResult{Name: name, Category: "use_cases", Status: "fail", Message: a.Name + ": key " + msg, Fix: fix})
		case empty:
			fix := unprintableNameFix
			if cmd, ok := storeKeyCommand("NEW_KEY", secretName, tenant, a.Name); ok {
				fix = "Replace it: " + cmd
			}
			out = append(out, CheckResult{Name: name, Category: "use_cases", Status: "fail", Message: fmt.Sprintf("%s: key secret %q is empty", a.Name, secretName), Fix: fix})
		default:
			out = append(out, CheckResult{Name: name, Category: "use_cases", Status: "pass", Message: fmt.Sprintf("%s (tenant %s): key secret %q resolves (value not shown)", a.Name, tenant, secretName)})
		}
	}
	return out
}

// discoveryProblem reports only typed failure categories. Neither an upstream
// response nor the transport's error text is safe to echo: a URL may embed
// credentials in userinfo/query, and a response can reflect auth headers.
func discoveryProblem(err error) string {
	var up *wire.UpstreamError
	if !errors.As(err, &up) {
		return localSourceProblem(err)
	}
	switch up.Kind {
	case wire.UpstreamKindTransport:
		return transportProblem(up.Err)
	case wire.UpstreamKindRPC:
		if up.RPC != nil {
			return fmt.Sprintf("the source answered a JSON-RPC error (code=%d category=%s)", up.RPC.Code, wire.RPCErrorCategory(up.RPC.Code))
		}
	case wire.UpstreamKindProtocol:
		if m := httpStatusRe.FindStringSubmatch(fmt.Sprint(up.Err)); errors.Is(err, wire.ErrUpstreamStatus) && m != nil {
			return "the source answered HTTP " + m[1]
		}
		return "the source's answer violates the MCP 2026-07-28 contract"
	case wire.UpstreamKindRequest:
		return "the discovery request could not be built"
	}
	return "upstream " + up.Kind + " error"
}

// localSourceProblem names a failure before anything was sent: the source's
// credential or its configuration, by typed error only.
func localSourceProblem(err error) string {
	switch {
	case errors.Is(err, secrets.ErrSecretNotFound), errors.Is(err, secrets.ErrVaultAbsent):
		return "source credential is not stored"
	case errors.Is(err, secrets.ErrSecretAccessDenied):
		return "source credential ACL denies this use case"
	case errors.Is(err, secrets.ErrSecretUndecryptable):
		return "source credential cannot be decrypted (restore the vault key)"
	default:
		return "local source configuration or credential error"
	}
}

// transportProblem names a transport failure by its type, never by its text
// (which can quote a credential-bearing URL).
func transportProblem(err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "transport error: connection refused"
	case errors.Is(err, context.DeadlineExceeded):
		return "transport error: timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "transport error: DNS lookup failed"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "transport error: timeout"
	}
	return "transport error (check address, TLS, DNS and egress)"
}

var httpStatusRe = regexp.MustCompile(`HTTP (\d{3})`)

// discoverTimeout bounds one source's discovery in doctor.
const discoverTimeout = 5 * time.Second

// checkActionSources runs the discovery talon serve runs at startup for
// every trusted MCP action source a use case declares (#431): a source that
// cannot be discovered stops serve from starting, so doctor says so first.
// Discovery is read-only (server/discover, tools/list); the source's
// credential is read from the vault read-only and never printed.
func checkActionSources(ctx context.Context, cfg *config.Config) []CheckResult {
	agents, err := useCases(ctx, cfg)
	if err != nil {
		return nil
	}
	vault, _ := secrets.OpenReadOnly(cfg.SecretsDBPath(), cfg.SecretsKey)
	var getter mcpsource.SecretGetter
	if vault != nil {
		defer vault.Close()
		getter = vault
	}
	d := mcpsource.New(getter)
	var out []CheckResult
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })
	for _, a := range agents {
		if a.Policy == nil || a.Policy.Actions == nil {
			continue
		}
		ids := make([]string, 0, len(a.Policy.Actions.Sources))
		for id := range a.Policy.Actions.Sources {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			src := a.Policy.Actions.Sources[id]
			if src.Type != "mcp" {
				continue
			}
			name := fmt.Sprintf("action_source:%s/%s", a.Name, id)
			dctx, cancel := context.WithTimeout(ctx, discoverTimeout)
			snap, derr := d.Discover(dctx, tenantOf(a.TenantID), a.Name, id, src)
			cancel()
			if derr != nil {
				out = append(out, CheckResult{
					Name: name, Category: "use_cases", Status: "fail",
					Message: fmt.Sprintf("MCP source %s of %s cannot be discovered: %s — talon serve will not start while it is unreachable", id, a.Name, discoveryProblem(derr)),
					Fix:     "Start the MCP server (or correct actions.sources." + id + ".url and its credential) before talon serve",
				})
				continue
			}
			out = append(out, CheckResult{
				Name: name, Category: "use_cases", Status: "pass",
				Message: fmt.Sprintf("MCP source %s of %s: discovered, %d tool(s)", id, a.Name, len(snap.Tools)),
			})
		}
	}
	return out
}
