// Command describe performs the gateway's startup probe against Talon's
// middleware endpoint exactly as OpenShell v0.1.3 does: a Describe RPC over
// TLS to the registered endpoint with the registration's CA, carrying the
// gateway's extension PeerMetadata. The live harness uses it in preflight
// mode (no Docker) to prove that a real gateway would accept the TLS
// identity and complete protocol negotiation; the manifest is printed. The
// manifest carries the request binding and, when Talon's response governance
// is on, the response binding (-expect-response requires it).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	extensionv1 "github.com/dativo-io/talon/internal/openshell/proto/gen/extensionv1"
	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
)

var expectResponse *bool

func main() {
	endpoint := flag.String("endpoint", "", "https://host:port of the Talon middleware listener (the registered grpc_endpoint)")
	caFile := flag.String("ca", "", "PEM certificate bundle the registration pins (tls_ca_cert_path)")
	expectResponse = flag.Bool("expect-response", false, "require the HTTP_RESPONSE / PRE_RETURN binding (Talon response governance on)")
	flag.Parse()
	if *endpoint == "" || *caFile == "" {
		log.Fatal("-endpoint and -ca are required")
	}
	pem, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatal("no certificates in CA bundle")
	}
	client := &http.Client{Transport: &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, Timeout: 10 * time.Second}
	dc := connect.NewClient[middlewarev1.MiddlewareDescribeRequest, middlewarev1.MiddlewareManifest](client, *endpoint+"/openshell.middleware.v1.SupervisorMiddleware/Describe", connect.WithGRPC())
	gateway := &extensionv1.PeerMetadata{
		ProtocolVersion:       &extensionv1.ProtocolVersion{Major: 1, Minor: 0},
		ImplementationName:    "openshell/gateway",
		ImplementationVersion: "0.1.3",
		SupportedCapabilities: []string{"openshell.supervisor-middleware.contract"},
		RequiredCapabilities:  []string{"openshell.supervisor-middleware.contract"},
	}
	res, err := dc.CallUnary(context.Background(), connect.NewRequest(&middlewarev1.MiddlewareDescribeRequest{Gateway: gateway}))
	if err != nil {
		log.Fatalf("describe: %v", err)
	}
	m := res.Msg
	bs := m.GetBindings()
	if err := checkBindings(bs, *expectResponse); err != nil {
		log.Fatalf("%v: %v", err, bs)
	}
	if m.GetExtension().GetProtocolVersion().GetMajor() != 1 {
		log.Fatalf("unexpected extension metadata: %v", m.GetExtension())
	}
	bindings := make([]map[string]any, 0, len(bs))
	for _, b := range bs {
		bindings = append(bindings, map[string]any{"operation": b.GetOperation().String(), "phase": b.GetPhase().String(), "max_payload_bytes": b.GetMaxPayloadBytes(), "request_timeout": b.GetRequestTimeout().AsDuration().String()})
	}
	out, _ := json.MarshalIndent(map[string]any{
		"name": m.GetName(), "expected_audience": m.GetExpectedAudience(),
		"bindings":  bindings,
		"extension": map[string]any{"protocol": fmt.Sprintf("%d.%d", m.GetExtension().GetProtocolVersion().GetMajor(), m.GetExtension().GetProtocolVersion().GetMinor()), "implementation": m.GetExtension().GetImplementationName() + " " + m.GetExtension().GetImplementationVersion(), "supported": m.GetExtension().GetSupportedCapabilities(), "required": m.GetExtension().GetRequiredCapabilities()},
	}, "", "  ")
	fmt.Println(string(out))
}

// checkBindings validates the manifest shape: the request binding first;
// the response binding (HTTP_RESPONSE / PRE_RETURN) second, only when
// Talon's response governance is on. expectResponse makes its presence a
// requirement so the harness proves the manifest the gateway will act on.
func checkBindings(bs []*middlewarev1.MiddlewareBinding, expectResponse bool) error {
	if len(bs) < 1 || len(bs) > 2 {
		return fmt.Errorf("unexpected binding count %d", len(bs))
	}
	if bs[0].GetOperation() != middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST ||
		bs[0].GetPhase() != middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS {
		return fmt.Errorf("first binding is not HTTP_REQUEST/PRE_CREDENTIALS")
	}
	if len(bs) == 2 && (bs[1].GetOperation() != middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_RESPONSE ||
		bs[1].GetPhase() != middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN) {
		return fmt.Errorf("second binding is not HTTP_RESPONSE/PRE_RETURN")
	}
	if expectResponse && len(bs) != 2 {
		return fmt.Errorf("response binding (HTTP_RESPONSE / PRE_RETURN) expected but not advertised")
	}
	return nil
}
