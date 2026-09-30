package openshell

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

// Shape from OpenShell v0.1.2 docs/observability/logging.mdx (OCSF 1.8.0).
const ocsfNetworkDenied = `{"class_uid":4001,"activity_name":"Open","severity_id":3,"status":"Failure","action":"Denied","disposition":"Blocked","status_detail":"no matching policy","message":"CONNECT denied httpbin.org:443","time":1790766000000,"dst_endpoint":{"domain":"httpbin.org","port":443},"actor":{"process":{"name":"/usr/bin/curl","pid":63}},"container":{"uid":"sb-0001"},"firewall_rule":{"name":"-","type":"opa"}}`

const ocsfHTTPAllowed = `{"class_uid":4002,"activity_name":"Post","action":"Allowed","disposition":"Allowed","message":"POST https://api.openai.com/v1/chat/completions","dst_endpoint":{"domain":"api.openai.com","port":443},"container":{"uid":"sb-0001"}}`

func TestParseOCSFLine(t *testing.T) {
	ev, err := ParseOCSFLine([]byte(ocsfNetworkDenied))
	require.NoError(t, err)
	require.Equal(t, 4001, ev.ClassUID)
	require.Equal(t, "network", ev.ClassName)
	require.Equal(t, "httpbin.org", ev.DstHost)
	require.Equal(t, 443, ev.DstPort)
	require.Equal(t, "/usr/bin/curl", ev.ProcessName)
	require.Equal(t, "sb-0001", ev.SandboxID)
	require.Equal(t, "no matching policy", ev.StatusDetail)
	require.Equal(t, "opa", ev.Engine)
	require.Equal(t, time.UnixMilli(1790766000000).UTC(), ev.Time)
	require.Len(t, ev.Digest, 64)

	_, err = ParseOCSFLine([]byte(ocsfHTTPAllowed))
	require.ErrorIs(t, err, ErrNotContainmentDenial, "allowed traffic is not a containment fact")
	_, err = ParseOCSFLine([]byte(`{"class_uid":1007,"action":"Denied"}`))
	require.ErrorIs(t, err, ErrNotContainmentDenial, "process events are out of scope")
	_, err = ParseOCSFLine([]byte(`{not json`))
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNotContainmentDenial, "corrupt export must not be silently skipped")
	_, err = ParseOCSFLine([]byte(`{"class_uid":4001,"action":"Denied","message":"` + strings.Repeat("x", maxOCSFLine) + `"}`))
	require.Error(t, err)
}

func TestReadOCSFDenials(t *testing.T) {
	in := strings.Join([]string{ocsfHTTPAllowed, "", ocsfNetworkDenied, ocsfNetworkDenied}, "\n")
	evs, skipped, err := ReadOCSFDenials(strings.NewReader(in), 10)
	require.NoError(t, err)
	require.Len(t, evs, 2)
	require.Equal(t, 2, skipped)
	_, _, err = ReadOCSFDenials(strings.NewReader(in), 1)
	require.Error(t, err, "bounded")
}

func TestContainmentRecord_LabelsExternalEnforcementHonestly(t *testing.T) {
	ev, err := ParseOCSFLine([]byte(ocsfNetworkDenied))
	require.NoError(t, err)
	rec := ContainmentRecord(ev, ImportedAgent{Name: "sandboxed-agent", TenantID: "acme", Team: "ops"}, "openshell-gateway:gw-1", "operator-x", time.Now())
	require.Equal(t, evidence.InvocationTypeExternalRuntimeEvent, rec.InvocationType)
	require.Equal(t, evidence.ClassExternalEvent, evidence.RecordClassOf(rec.InvocationType))
	require.Equal(t, "acme", rec.TenantID)
	require.Equal(t, "sandboxed-agent", rec.AgentID)
	require.Equal(t, "operator-x", rec.RequestSourceID)
	require.False(t, rec.PolicyDecision.Allowed)
	require.Equal(t, "external_runtime_deny", rec.PolicyDecision.Action)
	require.Equal(t, "openshell", rec.PolicyDecision.PolicyVersion, "rule name '-' does not become a policy ref")
	require.Equal(t, ev.Time, rec.Timestamp)
	e := rec.Enforcement
	require.Equal(t, evidence.MechanismVerify, e.Mechanism)
	require.Equal(t, evidence.BoundaryExternalRuntime, e.Boundary)
	require.Equal(t, evidence.BoundaryExternalRuntime, e.DecisionAuthority)
	require.Equal(t, evidence.ProvenanceExternalAsserted, e.Provenance)
	require.Equal(t, "sb-0001", e.Runtime.Reference)
	require.Equal(t, "openshell-gateway:gw-1", e.Runtime.ID)
	require.Equal(t, ReceiptKindOCSF, e.Receipt.Kind)
	require.False(t, e.Receipt.Verified, "an unsigned export can never be recorded as verified")
	require.Equal(t, ev.Digest, e.Receipt.Digest)
	require.Equal(t, evidence.WorkloadIdentityAsserted, rec.WorkloadIdentity.Status)
	require.Equal(t, sandboxSubjectPrefix+"sb-0001", rec.WorkloadIdentity.Subject)
	require.Len(t, rec.Explanations, 1)
	require.Equal(t, "EXTERNAL_RUNTIME_DENIED", rec.Explanations[0].Code)
	require.Contains(t, rec.Explanations[0].Reason, "Talon did not observe")
}
