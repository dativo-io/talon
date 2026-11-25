package effective

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/fleet"
)

// StatusOf is what `talon agents show` leads with and what the console's
// use-case list and page show (#575). Every next step maps to one headline;
// a BLOCKED health leads over the verification; the fleet's attention
// signals below blocked do not replace the verification's status; and with
// no verification nothing is claimed.
func TestStatusOf_HeadlineFollowsTheNextStepAndBlockedLeads(t *testing.T) {
	healthy := &fleet.AgentRow{Name: "app", TenantID: "default", Health: fleet.HealthHealthy, Why: "—"}
	headlines := map[string][2]string{
		NextNone:               {StatusWorking, "Working"},
		NextEnable:             {StatusDisabled, "Disabled"},
		NextStartRuntime:       {StatusNotActive, "Not active"},
		NextFixReload:          {StatusNotActive, "Not active"},
		NextWaitReload:         {StatusNotActive, "Not active"},
		NextCheckRuntime:       {StatusRuntimeNotConfirmed, "Runtime not confirmed"},
		NextSendRequest:        {StatusWaitingFirstRequest, "Waiting for its first request"},
		NextSendNewRequest:     {StatusNeedsAttention, "Needs attention"},
		NextCheckPolicy:        {StatusNeedsAttention, "Needs attention"},
		NextRestartRuntime:     {StatusNeedsAttention, "Needs attention"},
		NextUseCurrentKey:      {StatusNeedsAttention, "Needs attention"},
		NextStoreKey:           {StatusNeedsAttention, "Needs attention"},
		NextVerifyEvidence:     {StatusNeedsAttention, "Needs attention"},
		NextCheckEvidence:      {StatusNeedsAttention, "Needs attention"},
		NextUseAuthenticatedBy: {StatusNeedsAttention, "Needs attention"},
	}
	for code, want := range headlines {
		step := NextStep{Code: code, Text: "text of " + code, Commands: []string{"talon x"}}
		got := StatusOf(healthy, &Verification{Next: step})
		assert.Equal(t, want[0], got.Code, code)
		assert.Equal(t, want[1], got.Headline, code)
		require.NotNil(t, got.Next, code)
		assert.Equal(t, step, *got.Next, "the next step is the verification's, unchanged")
		assert.Nil(t, got.Also, code)
	}

	// Fleet attention below blocked is shown as health, not as the status
	// (as in the CLI): a budget warning on verified traffic is still Working.
	warn := *healthy
	warn.Health, warn.Why = fleet.HealthNeedsAttention, "daily budget 85% of cap ($8.50 / $10.00)"
	warn.Causes = []fleet.Cause{{Kind: fleet.CauseBudgetWarning, Detail: warn.Why}}
	assert.Equal(t, StatusWorking, StatusOf(&warn, &Verification{Next: NextStep{Code: NextNone}}).Code)

	// BLOCKED leads over verified traffic; "nothing to do" is not repeated.
	exhausted := *healthy
	exhausted.Health, exhausted.Why = fleet.HealthBlocked, "daily budget exhausted ($10.00 / $10.00)"
	exhausted.Causes = []fleet.Cause{{Kind: fleet.CauseBudgetExhausted, Detail: exhausted.Why}}
	got := StatusOf(&exhausted, &Verification{Next: NextStep{Code: NextNone, Text: "Nothing to do."}})
	assert.Equal(t, StatusBlocked, got.Code)
	assert.Equal(t, "Blocked", got.Headline)
	require.NotNil(t, got.Next)
	assert.Equal(t, NextBlocked, got.Next.Code)
	assert.Equal(t, "New requests of this use case are refused: daily budget exhausted ($10.00 / $10.00). They are served again when the period ends or the cap is raised (in the use case's file, within what the company policy allows).", got.Next.Text)
	assert.Equal(t, []string{"talon costs --agent app"}, got.Next.Commands)
	assert.Nil(t, got.Also, "'nothing to do' is not stated after a blocking condition")

	// A verification step that is itself an action is stated after it.
	got = StatusOf(&exhausted, &Verification{Next: NextStep{Code: NextStartRuntime, Text: "Start talon serve."}})
	assert.Equal(t, StatusBlocked, got.Code)
	require.NotNil(t, got.Also)
	assert.Equal(t, NextStartRuntime, got.Also.Code)

	for _, c := range []struct {
		kind fleet.CauseKind
		cmd  string
		text string
	}{
		{fleet.CausePolicyDenyAll, "talon agents show app --effective", "The full report shows the rule and the file that sets it."},
		{fleet.CauseInvalidConfig, "talon agents show app --effective", "The full report shows the rule and the file that sets it."},
		{"", "talon agents show app --effective", "The full report shows the policy and the spend behind it."},
	} {
		b := *healthy
		b.Health, b.Why, b.Causes = fleet.HealthBlocked, "", []fleet.Cause{{Kind: c.kind}}
		got := StatusOf(&b, nil)
		assert.Equal(t, StatusBlocked, got.Code, "blocked is known from the fleet row alone")
		require.NotNil(t, got.Next)
		assert.Contains(t, got.Next.Text, "a persistent condition refuses all new work")
		assert.Contains(t, got.Next.Text, c.text)
		assert.Equal(t, []string{c.cmd}, got.Next.Commands)
		assert.Nil(t, got.Also)
	}

	// No verification (the report could not be built): nothing is claimed.
	got = StatusOf(healthy, nil)
	assert.Equal(t, StatusNotDetermined, got.Code)
	assert.Nil(t, got.Next)
	assert.NotEqual(t, StatusWorking, StatusOf(nil, nil).Code)
}
