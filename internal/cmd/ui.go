package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/console"
	consoleserver "github.com/dativo-io/talon/internal/console/server"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/runtimestatus"
	talonsession "github.com/dativo-io/talon/internal/session"
)

// talon ui (#536, #537): the operations console is its own process. It opens
// the installation's store read-only, serves the embedded shell and the
// read API behind a one-time local pairing, and never touches the data
// plane: restarting it restarts no gateway or MCP traffic, and it holds no
// provider, admin or secrets key (the evidence signing key is needed only to
// verify signatures).
var (
	uiListen           string
	uiAllowNonLoopback bool
	uiAllowedHosts     []string
	uiSecureCookie     bool
	uiCodeTTL          time.Duration
	uiSessionTTL       time.Duration
	uiIdleTTL          time.Duration
	uiStoreWait        time.Duration
	uiPidFile          string
	uiGatewayConfig    string
	uiProxyConfig      string
	uiNoBrowser        bool
)

const (
	defaultUIListen = "127.0.0.1:8787"
	uiPidFileName   = "console.pid"
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Open the read-only operations console for this installation",
	Long: `Starts the console process on loopback, prints a one-time pairing code
to this terminal and opens the browser on the console page. The console
reads the installation's evidence store read-only and shares nothing with
the data plane: no gateway or MCP traffic runs through it.

Use "talon ui serve" for the long-running (container) form and
"talon ui pair" to print a fresh pairing code to a running console's log.`,
	RunE: func(cmd *cobra.Command, _ []string) error { return runUIServe(cmd, !uiNoBrowser) },
}

var uiServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the console process (headless; Docker Compose starts this)",
	Long: `Runs the console process until interrupted. On start it prints a one-time
pairing code to stdout (docker compose logs talon-ui); the code is single
use and expires within ten minutes. Reissue with "talon ui pair" or by
restarting the process.

The listener is loopback-only unless --allow-non-loopback is given, which
is what a container needs to publish the port; publish it to 127.0.0.1
on the host (the default Compose file does) unless a TLS terminator and a
trusted network sit in front.`,
	RunE: func(cmd *cobra.Command, _ []string) error { return runUIServe(cmd, false) },
}

var uiPairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Ask the running console process to print a fresh pairing code",
	Long: `Signals the console process named by its pid file to void the current
pairing code and print a new one to ITS stdout (the container log or the
terminal running the console). The code is never written anywhere else.`,
	RunE: runUIPair,
}

func init() {
	for _, c := range []*cobra.Command{uiCmd, uiServeCmd} {
		c.Flags().StringVar(&uiListen, "listen", defaultUIListen, "host:port to listen on (loopback unless --allow-non-loopback)")
		c.Flags().BoolVar(&uiAllowNonLoopback, "allow-non-loopback", false, "allow a non-loopback listen address (containers; needs a trusted network or TLS in front)")
		c.Flags().StringSliceVar(&uiAllowedHosts, "allowed-host", nil, "extra Host header name(s) the console answers, e.g. console.internal:8787 (repeatable)")
		c.Flags().BoolVar(&uiSecureCookie, "secure-cookie", false, "mark the session cookie Secure (behind a TLS terminator)")
		c.Flags().DurationVar(&uiCodeTTL, "code-ttl", 10*time.Minute, "validity of a pairing code (at most 10m)")
		c.Flags().DurationVar(&uiSessionTTL, "session-ttl", 8*time.Hour, "absolute lifetime of a browser session")
		c.Flags().DurationVar(&uiIdleTTL, "session-idle", time.Hour, "idle timeout of a browser session")
		c.Flags().DurationVar(&uiStoreWait, "store-wait", 30*time.Second, "how long to wait for the evidence store to appear (a data plane that is still starting)")
		c.Flags().StringVar(&uiPidFile, "pid-file", "", "pid file for 'talon ui pair' (default <data_dir>/"+uiPidFileName+")")
		c.Flags().StringVar(&uiGatewayConfig, "gateway-config", "", "gateway config for effective caps and the Configuration page (default $TALON_GATEWAY_CONFIG or talon.config.yaml)")
		c.Flags().StringVar(&uiProxyConfig, "proxy-config", "", "MCP proxy config shown read-only on the Configuration page (optional; the same file talon serve --proxy-config uses)")
	}
	uiCmd.Flags().BoolVar(&uiNoBrowser, "no-browser", false, "do not open the browser")
	uiPairCmd.Flags().StringVar(&uiPidFile, "pid-file", "", "pid file of the console process (default <data_dir>/"+uiPidFileName+")")
	uiCmd.AddCommand(uiServeCmd, uiPairCmd)
	rootCmd.AddCommand(uiCmd)
}

func runUIServe(cmd *cobra.Command, openBrowser bool) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if _, _, err := consoleserver.CheckListen(uiListen, uiAllowNonLoopback); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	inst, err := resolveConsoleInstallation(ctx, cfg, uiStoreWait)
	if err != nil {
		return err
	}
	defer inst.close()

	svc, err := console.New(console.Config{
		Evidence: inst.evidence, Sessions: inst.sessions, StorePath: inst.storePath, Currency: inst.currency,
		Fleet: inst.fleet, Budgets: console.FleetCapsBudgets{Fleet: inst.fleet}, ConfigSources: inst.sources,
		DataDir: cfg.DataDir, InstallationFingerprint: runtimestatus.Fingerprint(cfg.SigningKey),
		Version: resolvedVersion(), Commit: Commit,
	})
	if err != nil {
		return err
	}
	srv, err := consoleserver.New(svc, consoleserver.Options{
		Listen: uiListen, AllowNonLoopback: uiAllowNonLoopback, AllowedHosts: uiAllowedHosts, SecureCookie: uiSecureCookie,
		CodeTTL: uiCodeTTL, SessionTTL: uiSessionTTL, IdleTTL: uiIdleTTL, CodeOutput: cmd.OutOrStdout(),
	})
	if err != nil {
		return err
	}
	addr, err := srv.Listen(ctx)
	if err != nil {
		return err
	}
	pidPath := consolePidFile(cfg)
	if err := writePidFile(pidPath); err != nil {
		log.Warn().Err(err).Str("path", pidPath).Msg("console: pid file not written; 'talon ui pair' needs --pid-file")
	} else {
		defer os.Remove(pidPath)
	}
	log.Info().Str("addr", addr.String()).Str("store", inst.storePath).Str("currency", inst.currency).Msg("console: listening (read-only store, pairing required)")

	issue := func() {
		exp, err := srv.IssueCode()
		if err != nil {
			log.Error().Err(err).Msg("console: could not issue a pairing code")
			return
		}
		log.Info().Time("expires_at", exp).Msg("console: pairing code printed to stdout")
	}
	issue()
	reissue := reissueSignals(ctx)
	go func() {
		for range reissue {
			issue()
		}
	}()
	if openBrowser {
		url := "http://" + addr.String() + "/"
		if err := openInBrowser(ctx, url); err != nil {
			log.Warn().Err(err).Str("url", url).Msg("console: could not open the browser; open the URL yourself")
		}
	}
	return srv.Serve(ctx)
}

// consoleInstallation is what the console process reads: read-only store
// handles and the configuration files that define the fleet.
type consoleInstallation struct {
	storePath string
	currency  string
	sources   console.ConfigSources
	evidence  *evidence.Store
	sessions  *talonsession.Store
	fleet     console.FleetSource
}

func (c *consoleInstallation) close() {
	if c.sessions != nil {
		_ = c.sessions.Close()
	}
	if c.evidence != nil {
		_ = c.evidence.Close()
	}
}

// resolveConsoleInstallation fails closed: without a data directory or an
// evidence store (after storeWait) nothing listens; the error says what to
// start or point at. It creates nothing.
func resolveConsoleInstallation(ctx context.Context, cfg *config.Config, storeWait time.Duration) (*consoleInstallation, error) {
	if st, err := os.Stat(cfg.DataDir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("no Talon installation at %s (data_dir): run 'talon init' there, start 'talon serve', or set TALON_DATA_DIR / --config to the installation; the console creates nothing", cfg.DataDir)
	}
	const hint = "start 'talon serve' for this installation first (the console only reads the store it writes)"
	storePath := cfg.EvidenceDBPath()
	if err := waitForFile(ctx, storePath, storeWait); err != nil {
		return nil, fmt.Errorf("evidence store %s not found after %s: %s — %w", storePath, storeWait, hint, err)
	}
	ev, err := evidence.OpenReadOnly(storePath, cfg.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("opening evidence store read-only: %w — %s", err, hint)
	}
	ss, err := talonsession.OpenReadOnly(storePath)
	if err != nil {
		_ = ev.Close()
		return nil, fmt.Errorf("opening session store read-only: %w — %s", err, hint)
	}
	gatewayCfg := strings.TrimSpace(uiGatewayConfig)
	if gatewayCfg == "" {
		gatewayCfg = strings.TrimSpace(os.Getenv("TALON_GATEWAY_CONFIG"))
	}
	if gatewayCfg == "" {
		gatewayCfg = "talon.config.yaml"
	}
	currency := loadPricingTable(cfg, "").CurrencyCode()
	return &consoleInstallation{
		storePath: storePath, currency: currency, evidence: ev, sessions: ss,
		sources: console.ConfigSources{AgentsDir: cfg.AgentsDir, DefaultPolicy: cfg.DefaultPolicy, GatewayConfig: gatewayCfg, ProxyConfig: strings.TrimSpace(uiProxyConfig)},
		fleet:   console.OfflineFleetSource(cfg.AgentsDir, cfg.DefaultPolicy, gatewayCfg, currency, ev, ss, nil),
	}, nil
}

func waitForFile(ctx context.Context, path string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if time.Now().After(deadline) {
			return os.ErrNotExist
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func consolePidFile(cfg *config.Config) string {
	if p := strings.TrimSpace(uiPidFile); p != "" {
		return p
	}
	return filepath.Join(cfg.DataDir, uiPidFileName)
}

func writePidFile(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
}

func runUIPair(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	path := consolePidFile(cfg)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the pid file path comes from the operator's flag or data_dir
	if err != nil {
		return fmt.Errorf("no running console found (%s): start 'talon ui serve' or pass --pid-file — %w", path, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return fmt.Errorf("pid file %s does not hold a pid", path)
	}
	if err := requestReissue(pid); err != nil {
		return fmt.Errorf("console process %d not reachable (%w); if it is gone, remove %s and start 'talon ui serve'", pid, err, path)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Asked console process %d for a new pairing code. Read it from that process's output (docker compose logs talon-ui, or its terminal); the previous code is void.\n", pid)
	return nil
}
