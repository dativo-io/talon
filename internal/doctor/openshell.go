package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/workload"
)

// OpenShell composition checks (#482/#457). They run only when
// gateway.openshell is enabled and answer the questions an operator asks
// before registering Talon with a real gateway: will the gateway trust the
// transport, can Talon verify the gateway's tokens, is any sandbox bound,
// can the Action Gateway hop mint assertions, and is the response side on.
func checkOpenShell(ctx context.Context, gwCfg *gateway.GatewayConfig, opts Options) []CheckResult {
	oc := gwCfg.OpenShell
	if oc == nil || !oc.Enabled {
		return nil
	}
	results := []CheckResult{
		checkOpenShellTransport(oc),
		checkOpenShellIdentityKeys(ctx, oc, opts.SkipUpstream),
		checkOpenShellBindings(ctx),
		checkOpenShellSelfDestination(oc),
		checkOpenShellResponseGovernance(oc),
	}
	return results
}

// checkOpenShellTransport: the gateway registers Talon with an https
// grpc_endpoint and verifies Talon's certificate against platform roots or
// tls_ca_cert_path with normal hostname verification, so the pair must load,
// carry serverAuth and a SAN, and not be expired.
func checkOpenShellTransport(oc *gateway.OpenShellConfig) CheckResult {
	name := "openshell_transport"
	if oc.AllowInsecureTransport {
		return CheckResult{
			Name: name, Category: "openshell", Status: "warn",
			Message: fmt.Sprintf("plaintext h2c on %s (allow_insecure_transport): OpenShell sends no caller token over an insecure registration, so every real request is denied", oc.Listen),
			Fix:     "Serve TLS (tls.cert_file/key_file) and register https://<host>:<port> with tls_ca_cert_path; keep insecure transport for local fixtures only",
		}
	}
	pair, err := tls.LoadX509KeyPair(oc.TLS.CertFile, oc.TLS.KeyFile)
	if err != nil {
		return CheckResult{Name: name, Category: "openshell", Status: "fail", Message: fmt.Sprintf("TLS identity does not load: %v", err), Fix: "Point tls.cert_file/key_file at a server certificate signed by the CA you give OpenShell as tls_ca_cert_path (a self-signed leaf is not a trust anchor for OpenShell)"}
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return CheckResult{Name: name, Category: "openshell", Status: "fail", Message: fmt.Sprintf("certificate does not parse: %v", err)}
	}
	var problems []string
	if time.Now().After(leaf.NotAfter) {
		problems = append(problems, "expired "+leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		problems = append(problems, "no SAN (OpenShell verifies the dialed host against SANs)")
	}
	serverAuth := len(leaf.ExtKeyUsage) == 0
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageAny {
			serverAuth = true
		}
	}
	if !serverAuth {
		problems = append(problems, "no serverAuth EKU")
	}
	if leaf.Issuer.String() == leaf.Subject.String() && len(pair.Certificate) == 1 {
		problems = append(problems, "self-signed leaf (OpenShell's tls_ca_cert_path must be a CA that signed this certificate)")
	}
	if len(problems) > 0 {
		return CheckResult{Name: name, Category: "openshell", Status: "fail", Message: strings.Join(problems, "; "), Fix: "Issue a server certificate from an operator CA with serverAuth EKU and SANs for every address the gateway and supervisors dial; register the CA as tls_ca_cert_path"}
	}
	return CheckResult{Name: name, Category: "openshell", Status: "pass", Message: fmt.Sprintf("TLS identity on %s: SANs %v, valid until %s", oc.Listen, append(leaf.DNSNames, ipStrings(leaf.IPAddresses)...), leaf.NotAfter.UTC().Format(time.RFC3339))}
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// checkOpenShellIdentityKeys: Talon must be able to verify the gateway's
// EdDSA extension tokens, so the configured key source must yield keys.
func checkOpenShellIdentityKeys(ctx context.Context, oc *gateway.OpenShellConfig, skipUpstream bool) CheckResult {
	name := "openshell_identity_keys"
	switch {
	case oc.Identity.JWKSFile != "":
		ks, err := workload.LoadJWKSFile(oc.Identity.JWKSFile)
		if err != nil {
			return CheckResult{Name: name, Category: "openshell", Status: "fail", Message: fmt.Sprintf("jwks_file: %v", err), Fix: "Export the gateway's JWKS (<gateway>/.well-known/jwks.json) to this path, or use jwks_url"}
		}
		return CheckResult{Name: name, Category: "openshell", Status: "pass", Message: fmt.Sprintf("jwks_file %s: %d Ed25519 key(s); issuer %s, audience %s", oc.Identity.JWKSFile, ks.Len(), oc.Identity.Issuer, oc.Identity.Audience)}
	case skipUpstream:
		return CheckResult{Name: name, Category: "openshell", Status: "warn", Message: "jwks_url not probed (--skip-upstream)"}
	default:
		client := &http.Client{Timeout: 5 * time.Second}
		ks := workload.NewRemoteKeySet(oc.Identity.JWKSURL, client)
		_, _, err := ks.Key("talon-doctor-probe")
		if err != nil {
			return CheckResult{Name: name, Category: "openshell", Status: "fail", Message: fmt.Sprintf("jwks_url %s unreachable: %v", oc.Identity.JWKSURL, err), Fix: "The gateway must be running with gateway_jwt configured and reachable from this host over TLS; verification fails closed without keys"}
		}
		_ = ctx
		return CheckResult{Name: name, Category: "openshell", Status: "pass", Message: fmt.Sprintf("jwks_url %s reachable; issuer %s, audience %s", oc.Identity.JWKSURL, oc.Identity.Issuer, oc.Identity.Audience)}
	}
}

// checkOpenShellBindings: without a bound sandbox every delegated request
// is workload_identity_unbound.
func checkOpenShellBindings(ctx context.Context) CheckResult {
	name := "openshell_bindings"
	cfg, err := config.Load()
	if err != nil {
		return CheckResult{Name: name, Category: "openshell", Status: "warn", Message: "operator config not loaded: " + err.Error()}
	}
	var scan *agentcatalog.ScanResult
	if cfg.AgentsDir != "" {
		scan, err = agentcatalog.DiscoverAgents(ctx, cfg.AgentsDir)
	} else {
		scan, err = agentcatalog.Source{File: cfg.DefaultPolicy}.Scan(ctx)
	}
	if err != nil && (scan == nil || len(scan.Agents) == 0) {
		return CheckResult{Name: name, Category: "openshell", Status: "warn", Message: "agents not loaded: " + err.Error()}
	}
	bound, agents := 0, 0
	for i := range scan.Agents {
		a := &scan.Agents[i]
		if a.Policy == nil || a.Policy.Agent.WorkloadIdentity == nil {
			continue
		}
		n := 0
		for _, b := range a.Policy.Agent.WorkloadIdentity.Bindings {
			if strings.EqualFold(strings.TrimSpace(b.Runtime), "openshell") {
				n++
			}
		}
		if n > 0 {
			agents++
			bound += n
		}
	}
	if bound == 0 {
		return CheckResult{Name: name, Category: "openshell", Status: "warn", Message: "no agent binds an OpenShell sandbox subject; every delegated request will be denied workload_identity_unbound", Fix: "Add agent.workload_identity.bindings: [{runtime: openshell, subject: \"spiffe://openshell/sandbox/<sandbox_id>\"}] to the use case (picked up by the agent reload)"}
	}
	return CheckResult{Name: name, Category: "openshell", Status: "pass", Message: fmt.Sprintf("%d sandbox binding(s) across %d use case(s)", bound, agents)}
}

// checkOpenShellSelfDestination: the Action Gateway hop needs a root key of
// at least 32 bytes to derive the assertion key.
func checkOpenShellSelfDestination(oc *gateway.OpenShellConfig) CheckResult {
	name := "openshell_self_destination"
	if oc.SelfDestination == nil {
		return CheckResult{Name: name, Category: "openshell", Status: "pass", Message: "not configured: sandboxes cannot reach Talon's Action Gateway through the hop (model governance only)"}
	}
	cfg, err := config.Load()
	if err != nil {
		// Without a loadable operator config (typically an invalid secrets
		// key) no assertion key exists and talon serve refuses to start.
		return CheckResult{Name: name, Category: "openshell", Status: "fail", Message: "operator config not loaded: " + err.Error(), Fix: "Fix the operator config; self_destination needs a valid 32-byte TALON_SECRETS_KEY"}
	}
	if len(strings.TrimSpace(cfg.SecretsKey)) < 32 {
		return CheckResult{Name: name, Category: "openshell", Status: "fail", Message: "TALON_SECRETS_KEY is shorter than 32 bytes; workload assertions cannot be minted and talon serve refuses to start", Fix: "Set a 32-byte TALON_SECRETS_KEY (the same value on every Talon instance that verifies assertions)"}
	}
	return CheckResult{Name: name, Category: "openshell", Status: "pass", Message: fmt.Sprintf("hosts %v, assertion ttl %s; sandboxes authenticate to the Action Gateway through the hop", oc.SelfDestination.Hosts, oc.SelfDestination.AssertionTTLDuration())}
}

// checkOpenShellResponseGovernance: without the response hook cost is
// estimate-only and the response is ungoverned.
func checkOpenShellResponseGovernance(oc *gateway.OpenShellConfig) CheckResult {
	name := "openshell_response_governance"
	if !oc.ResponseGovernanceEnabled() {
		return CheckResult{Name: name, Category: "openshell", Status: "warn", Message: "disabled: cost is estimate-only, token counts are zero and the provider response is not governed on this path", Fix: "Set gateway.openshell.response_governance.enabled: true and restart the OpenShell gateway so it reads the new manifest"}
	}
	return CheckResult{Name: name, Category: "openshell", Status: "pass", Message: fmt.Sprintf("enabled: settlement timeout %s, capture bound %d bytes, ledger bound %d pending settlements (new requests are refused beyond it), settled rows kept %s", oc.ResponseGovernance.SettlementTimeoutDuration(), oc.ResponseGovernance.MaxCaptureBytes, oc.ResponseGovernance.MaxPendingSettlements(), oc.ResponseGovernance.LedgerRetentionDuration())}
}
