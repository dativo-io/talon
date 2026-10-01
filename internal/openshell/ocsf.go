package openshell

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
)

// OpenShell containment facts (#482 VERIFY path).
//
// OpenShell enforces network/filesystem/process containment itself and
// never consults Talon for it. The only trace an external system gets is
// OpenShell's OCSF event export (v0.1.2: OCSF 1.8.0 JSONL, classes 4001
// Network Activity and 4002 HTTP Activity for denials). Talon can IMPORT
// those facts into its signed timeline so one use case's history shows
// what OpenShell blocked next to what Talon decided — labelled honestly:
// the runtime enforced it, Talon did not observe it, and the export is
// unsigned, so the receipt is recorded as unverified.

// ErrNotContainmentDenial marks an OCSF line that is not a network/HTTP
// denial (allowed traffic, process events, config events) and is skipped.
var ErrNotContainmentDenial = errors.New("not an OpenShell containment denial")

// ReceiptKindOCSF names the imported receipt kind in evidence.
const ReceiptKindOCSF = "openshell_ocsf"

// maxOCSFLine bounds one imported event line.
const maxOCSFLine = 64 * 1024

// ContainmentEvent is one imported OpenShell denial (safe fields only).
type ContainmentEvent struct {
	ClassUID     int
	ClassName    string // "network" | "http"
	ActivityName string
	Action       string
	Disposition  string
	StatusDetail string
	Message      string
	DstHost      string
	DstPort      int
	ProcessName  string
	SandboxID    string
	PolicyName   string
	Engine       string
	Time         time.Time // zero when absent
	Digest       string    // sha256 of the raw line
}

type ocsfLine struct {
	ClassUID     int    `json:"class_uid"`
	ActivityName string `json:"activity_name"`
	Action       string `json:"action"`
	Disposition  string `json:"disposition"`
	StatusDetail string `json:"status_detail"`
	Message      string `json:"message"`
	Time         int64  `json:"time"`
	DstEndpoint  struct {
		Domain string `json:"domain"`
		Port   int    `json:"port"`
	} `json:"dst_endpoint"`
	Actor struct {
		Process struct {
			Name string `json:"name"`
		} `json:"process"`
	} `json:"actor"`
	Container struct {
		UID string `json:"uid"`
	} `json:"container"`
	FirewallRule struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"firewall_rule"`
}

// ParseOCSFLine parses one OCSF JSON line and returns it when it is a
// network (4001) or HTTP (4002) DENIAL. Everything else returns
// ErrNotContainmentDenial. Malformed JSON is an error so a corrupt export
// is not silently skipped.
func ParseOCSFLine(line []byte) (*ContainmentEvent, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil, ErrNotContainmentDenial
	}
	if len(line) > maxOCSFLine {
		return nil, fmt.Errorf("ocsf line exceeds %d bytes", maxOCSFLine)
	}
	var raw ocsfLine
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("ocsf json: %w", err)
	}
	var class string
	switch raw.ClassUID {
	case 4001:
		class = "network"
	case 4002:
		class = "http"
	default:
		return nil, ErrNotContainmentDenial
	}
	if !strings.EqualFold(raw.Action, "Denied") && !strings.EqualFold(raw.Disposition, "Blocked") {
		return nil, ErrNotContainmentDenial
	}
	ev := &ContainmentEvent{
		ClassUID:     raw.ClassUID,
		ClassName:    class,
		ActivityName: raw.ActivityName,
		Action:       raw.Action,
		Disposition:  raw.Disposition,
		StatusDetail: bound(raw.StatusDetail, 256),
		Message:      bound(raw.Message, 256),
		DstHost:      bound(raw.DstEndpoint.Domain, 253),
		DstPort:      raw.DstEndpoint.Port,
		ProcessName:  bound(raw.Actor.Process.Name, 256),
		SandboxID:    bound(raw.Container.UID, 128),
		PolicyName:   bound(raw.FirewallRule.Name, 128),
		Engine:       bound(raw.FirewallRule.Type, 32),
		Digest:       ReceiptDigest(line),
	}
	if raw.Time > 0 {
		// OCSF time is epoch milliseconds.
		ev.Time = time.UnixMilli(raw.Time).UTC()
	}
	return ev, nil
}

func bound(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ImportedAgent is the use case an imported event attributes to.
type ImportedAgent struct {
	Name     string
	TenantID string
	Team     string
}

// ContainmentRecord builds the signed record for one imported denial.
// issuer is the configured OpenShell runtime identity (gateway issuer);
// operator names who ran the import (request_source_id).
func ContainmentRecord(ev *ContainmentEvent, agent ImportedAgent, issuer, operator string, now time.Time) *evidence.Evidence {
	ts := ev.Time
	if ts.IsZero() {
		ts = now.UTC()
	}
	tenant := agent.TenantID
	if tenant == "" {
		tenant = "default"
	}
	dst := ev.DstHost
	if ev.DstPort > 0 {
		dst = fmt.Sprintf("%s:%d", ev.DstHost, ev.DstPort)
	}
	reasons := []string{"openshell " + ev.ClassName + " denied: " + dst}
	if ev.StatusDetail != "" {
		reasons = append(reasons, "openshell status_detail: "+ev.StatusDetail)
	}
	if ev.ProcessName != "" {
		reasons = append(reasons, "openshell process: "+ev.ProcessName)
	}
	policyRef := "openshell"
	if ev.PolicyName != "" && ev.PolicyName != "-" {
		policyRef = "openshell:" + ev.PolicyName
	}
	return &evidence.Evidence{
		ID:              "ext_" + uuid.New().String()[:12],
		CorrelationID:   "ext_" + ev.Digest[:12],
		Timestamp:       ts,
		TenantID:        tenant,
		AgentID:         agent.Name,
		Team:            agent.Team,
		InvocationType:  evidence.InvocationTypeExternalRuntimeEvent,
		RequestSourceID: operator,
		PolicyDecision: evidence.PolicyDecision{
			Allowed:       false,
			Action:        "external_runtime_deny",
			Reasons:       reasons,
			PolicyVersion: policyRef,
		},
		AuditTrail: evidence.AuditTrail{InputHash: ev.Digest},
		Status:     "denied",
		Explanations: []explanation.Item{{
			Code:      "EXTERNAL_RUNTIME_DENIED",
			Decision:  explanation.DecisionDeny,
			Stage:     explanation.StageExternalRuntime,
			Reason:    "OpenShell's OCSF export asserts it denied " + ev.ClassName + " access to " + dst + " (unsigned operator import; Talon did not observe or verify this)",
			PolicyRef: policyRef,
		}},
		WorkloadIdentity: &evidence.WorkloadIdentity{
			Status:  evidence.WorkloadIdentityAsserted,
			Runtime: RuntimeType,
			Subject: sandboxSubjectPrefix + ev.SandboxID,
			Binding: evidence.WorkloadIdentityBindingAgentConfig,
		},
		// An unsigned, operator-imported export is an ASSERTION. Talon's
		// signature proves Talon recorded the assertion, nothing more.
		Enforcement: &evidence.Enforcement{
			Mechanism:         evidence.MechanismVerify,
			Boundary:          evidence.BoundaryExternalRuntime,
			DecisionAuthority: evidence.BoundaryExternalRuntime,
			Provenance:        evidence.ProvenanceExternalAsserted,
			Runtime: &evidence.ExternalRuntimeRef{
				Type: RuntimeType, ID: issuer, PolicyRef: ev.PolicyName, Reference: ev.SandboxID,
			},
			Receipt: &evidence.ExternalReceipt{
				Kind: ReceiptKindOCSF, Digest: ev.Digest, Verified: false, Detail: ev.StatusDetail,
			},
		},
	}
}

// ReadOCSFDenials scans a JSONL export and returns every containment
// denial, skipping non-denial lines. Malformed lines abort the import.
func ReadOCSFDenials(r io.Reader, maxEvents int) ([]*ContainmentEvent, int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxOCSFLine+1)
	var out []*ContainmentEvent
	skipped := 0
	for sc.Scan() {
		ev, err := ParseOCSFLine(sc.Bytes())
		if errors.Is(err, ErrNotContainmentDenial) {
			skipped++
			continue
		}
		if err != nil {
			return nil, skipped, err
		}
		out = append(out, ev)
		if maxEvents > 0 && len(out) > maxEvents {
			return nil, skipped, fmt.Errorf("export contains more than %d denials; split the file", maxEvents)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, skipped, err
	}
	return out, skipped, nil
}
