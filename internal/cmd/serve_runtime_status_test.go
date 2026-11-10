package cmd

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/internal/runtimestatus"
	"github.com/dativo-io/talon/internal/secrets"
)

// The startup-failure record carries a fixed code and sentence; the raw
// error (secret names, paths, configuration content) never reaches it.
func TestClassifyStartupFailure(t *testing.T) {
	wrapped := func(e error) error {
		return fmt.Errorf("building agent identity registry: agent %q (/srv/agents/hr.yaml): resolving key secret %q: %w", "hr", "hr-talon-key", e)
	}
	cases := []struct {
		err  error
		code string
	}{
		{wrapped(fmt.Errorf("decrypting secret: %w: %w", secrets.ErrSecretUndecryptable, errors.New("cipher: message authentication failed"))), runtimestatus.FailureAgentKeyUnavailable},
		{wrapped(secrets.ErrSecretNotFound), runtimestatus.FailureAgentKeyUnavailable},
		{wrapped(secrets.ErrSecretAccessDenied), runtimestatus.FailureAgentKeyUnavailable},
		{fmt.Errorf("initializing secrets: %w", secrets.ErrInvalidEncryptionKey), runtimestatus.FailureSecretsStore},
		{fmt.Errorf("%w: add agent.key.secret_name", errNoKeyedAgents), runtimestatus.FailureNoKeyedAgents},
		{errors.New("loading policy: yaml: line 3: password: hunter2"), runtimestatus.FailureConfiguration},
	}
	for _, c := range cases {
		f := classifyStartupFailure(c.err)
		assert.Equal(t, c.code, f.Code, c.err.Error())
		assert.NotEmpty(t, f.Reason)
		for _, leak := range []string{"hr-talon-key", "/srv/agents", "hunter2", "cipher:"} {
			assert.False(t, strings.Contains(f.Reason, leak), "reason %q copies %q", f.Reason, leak)
		}
	}
}
