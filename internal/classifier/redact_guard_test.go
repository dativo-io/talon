package classifier

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactGuard_VerifyPassesWhenNoPII(t *testing.T) {
	s := MustNewScanner()
	guard := NewRedactGuard(s)
	require.NoError(t, guard.Verify(context.Background(), "hello world"))
}

func TestRedactGuard_VerifyBlocksResidualPII(t *testing.T) {
	s := MustNewScanner()
	guard := NewRedactGuard(s)
	err := guard.Verify(context.Background(), "Contact me at user@example.com")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPIIDetected))
	var residual *ResidualPIIError
	require.ErrorAs(t, err, &residual)
	assert.Contains(t, residual.Types, "email")
	assert.Greater(t, residual.Count, 0)
}
