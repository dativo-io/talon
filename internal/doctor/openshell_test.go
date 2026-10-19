package doctor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/gateway"
)

func writeCertPair(t *testing.T, dir string, selfSigned, serverAuth, san bool) (certPath, keyPath string) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "talon-test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "talon"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if serverAuth {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if san {
		leaf.DNSNames = []string{"host.openshell.internal"}
		leaf.IPAddresses = []net.IP{net.ParseIP("10.0.0.5")}
	}
	parent, parentKey := ca, caKey
	if selfSigned {
		leaf.Subject = pkix.Name{CommonName: "self"}
		leaf.Issuer = leaf.Subject
		parent, parentKey = leaf, leafKey
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, &leafKey.PublicKey, parentKey)
	require.NoError(t, err)
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}), 0o600))
	return certPath, keyPath
}

func writeJWKS(t *testing.T, dir string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	doc := map[string]any{"keys": []map[string]any{{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": base64.RawURLEncoding.EncodeToString(pub)}}}
	b, _ := json.Marshal(doc)
	p := filepath.Join(dir, "jwks.json")
	require.NoError(t, os.WriteFile(p, b, 0o600))
	return p
}

func findCheck(results []CheckResult, name string) *CheckResult {
	for i := range results {
		if results[i].Name == name {
			return &results[i]
		}
	}
	return nil
}

func TestOpenShellChecks_TransportAndKeys(t *testing.T) {
	dir := t.TempDir()
	goodCert, goodKey := writeCertPair(t, dir, false, true, true)
	jwks := writeJWKS(t, dir)
	base := func() *gateway.OpenShellConfig {
		return &gateway.OpenShellConfig{
			Enabled: true, Listen: "10.0.0.5:50051",
			TLS:      gateway.OpenShellTLSConfig{CertFile: goodCert, KeyFile: goodKey},
			Identity: gateway.OpenShellIdentityConfig{Issuer: "openshell-gateway:gw-1", Audience: "urn:openshell:extension:middleware:talon", JWKSFile: jwks},
		}
	}

	t.Run("good identity passes", func(t *testing.T) {
		r := checkOpenShellTransport(base())
		assert.Equal(t, "pass", r.Status, r.Message)
		assert.Contains(t, r.Message, "host.openshell.internal")
		k := checkOpenShellIdentityKeys(context.Background(), base(), true)
		assert.Equal(t, "pass", k.Status, k.Message)
		assert.Contains(t, k.Message, "1 Ed25519 key(s)")
	})
	t.Run("insecure transport warns", func(t *testing.T) {
		c := base()
		c.AllowInsecureTransport = true
		r := checkOpenShellTransport(c)
		assert.Equal(t, "warn", r.Status)
	})
	t.Run("self-signed leaf fails", func(t *testing.T) {
		cert, key := writeCertPair(t, t.TempDir(), true, true, true)
		c := base()
		c.TLS = gateway.OpenShellTLSConfig{CertFile: cert, KeyFile: key}
		r := checkOpenShellTransport(c)
		assert.Equal(t, "fail", r.Status)
		assert.Contains(t, r.Message, "self-signed")
	})
	t.Run("no serverAuth and no SAN fail", func(t *testing.T) {
		cert, key := writeCertPair(t, t.TempDir(), false, false, false)
		c := base()
		c.TLS = gateway.OpenShellTLSConfig{CertFile: cert, KeyFile: key}
		r := checkOpenShellTransport(c)
		assert.Equal(t, "fail", r.Status)
		assert.Contains(t, r.Message, "serverAuth")
		assert.Contains(t, r.Message, "SAN")
	})
	t.Run("missing files fail", func(t *testing.T) {
		c := base()
		c.TLS = gateway.OpenShellTLSConfig{CertFile: filepath.Join(dir, "nope.pem"), KeyFile: goodKey}
		assert.Equal(t, "fail", checkOpenShellTransport(c).Status)
		c = base()
		c.Identity.JWKSFile = filepath.Join(dir, "nope.json")
		assert.Equal(t, "fail", checkOpenShellIdentityKeys(context.Background(), c, true).Status)
	})
	t.Run("jwks_url skipped offline, unreachable fails", func(t *testing.T) {
		c := base()
		c.Identity.JWKSFile, c.Identity.JWKSURL = "", "https://127.0.0.1:1/.well-known/jwks.json"
		assert.Equal(t, "warn", checkOpenShellIdentityKeys(context.Background(), c, true).Status)
		assert.Equal(t, "fail", checkOpenShellIdentityKeys(context.Background(), c, false).Status)
	})
}

func TestOpenShellChecks_SelfDestinationAndResponse(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	c := &gateway.OpenShellConfig{Enabled: true}
	assert.Equal(t, "pass", checkOpenShellSelfDestination(c).Status, "unconfigured hop is a pass with an explicit statement")
	assert.Equal(t, "warn", checkOpenShellResponseGovernance(c).Status, "no response governance: estimate-only is a warning")

	c.SelfDestination = &gateway.OpenShellSelfDestinationConfig{Hosts: []string{"talon.internal"}}
	t.Setenv("TALON_SECRETS_KEY", "short")
	assert.Equal(t, "fail", checkOpenShellSelfDestination(c).Status)
	t.Setenv("TALON_SECRETS_KEY", "12345678901234567890123456789012")
	r := checkOpenShellSelfDestination(c)
	assert.Equal(t, "pass", r.Status, r.Message)
	assert.Contains(t, r.Message, "talon.internal")

	c.ResponseGovernance = &gateway.OpenShellResponseGovernanceConfig{Enabled: true, SettlementTimeout: "5m", MaxCaptureBytes: 1 << 20}
	r = checkOpenShellResponseGovernance(c)
	assert.Equal(t, "pass", r.Status)
	assert.Contains(t, r.Message, "5m")
}

// The checks appear in a doctor run only when the OpenShell block is on.
func TestRun_OpenShellCategory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SECRETS_KEY", "12345678901234567890123456789012")
	jwks := writeJWKS(t, dir)
	gwCfgPath := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(gwCfgPath, []byte(`gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
  openshell:
    enabled: true
    listen: "127.0.0.1:50051"
    allow_insecure_transport: true
    identity:
      issuer: "openshell-gateway:gw-1"
      audience: "urn:openshell:extension:middleware:talon"
      jwks_file: "`+jwks+`"
    self_destination:
      hosts: ["talon.internal"]
`), 0o600))
	report := Run(context.Background(), Options{GatewayConfigPath: gwCfgPath, SkipUpstream: true})
	names := map[string]string{}
	for _, c := range report.Checks {
		if c.Category == "openshell" {
			names[c.Name] = c.Status
		}
	}
	assert.Equal(t, "warn", names["openshell_transport"])
	assert.Equal(t, "pass", names["openshell_identity_keys"])
	assert.Equal(t, "pass", names["openshell_self_destination"])
	assert.Equal(t, "warn", names["openshell_response_governance"])
	assert.Contains(t, names, "openshell_bindings")
	require.NotNil(t, findCheck(report.Checks, "openshell_bindings"))

	// Off: no openshell checks at all.
	require.NoError(t, os.WriteFile(gwCfgPath, []byte("gateway:\n  enabled: true\n  listen_prefix: \"/v1/proxy\"\n"), 0o600))
	report = Run(context.Background(), Options{GatewayConfigPath: gwCfgPath, SkipUpstream: true})
	for _, c := range report.Checks {
		assert.NotEqual(t, "openshell", c.Category)
	}
}
