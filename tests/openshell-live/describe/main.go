// Command describe performs the gateway's startup probe against Talon's
// middleware endpoint exactly as OpenShell v0.1.3 does: a Describe RPC over
// TLS to the registered endpoint with the registration's CA, carrying the
// gateway's extension PeerMetadata. The live harness uses it in preflight
// mode (no Docker) to prove that a real gateway would accept the TLS
// identity and complete protocol negotiation; the manifest is printed.
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

func main() {
	endpoint := flag.String("endpoint", "", "https://host:port of the Talon middleware listener (the registered grpc_endpoint)")
	caFile := flag.String("ca", "", "PEM certificate bundle the registration pins (tls_ca_cert_path)")
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
	if len(m.GetBindings()) != 1 || m.GetBindings()[0].GetOperation() != middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST ||
		m.GetBindings()[0].GetPhase() != middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS {
		log.Fatalf("unexpected bindings: %v", m.GetBindings())
	}
	if m.GetExtension().GetProtocolVersion().GetMajor() != 1 {
		log.Fatalf("unexpected extension metadata: %v", m.GetExtension())
	}
	out, _ := json.MarshalIndent(map[string]any{
		"name": m.GetName(), "expected_audience": m.GetExpectedAudience(),
		"binding":   map[string]any{"operation": m.GetBindings()[0].GetOperation().String(), "phase": m.GetBindings()[0].GetPhase().String(), "max_payload_bytes": m.GetBindings()[0].GetMaxPayloadBytes(), "request_timeout": m.GetBindings()[0].GetRequestTimeout().AsDuration().String()},
		"extension": map[string]any{"protocol": fmt.Sprintf("%d.%d", m.GetExtension().GetProtocolVersion().GetMajor(), m.GetExtension().GetProtocolVersion().GetMinor()), "implementation": m.GetExtension().GetImplementationName() + " " + m.GetExtension().GetImplementationVersion(), "supported": m.GetExtension().GetSupportedCapabilities(), "required": m.GetExtension().GetRequiredCapabilities()},
	}, "", "  ")
	fmt.Println(string(out))
}
