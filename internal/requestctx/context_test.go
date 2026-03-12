package requestctx

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetTenantID_and_TenantID(t *testing.T) {
	ctx := context.Background()
	assert.Empty(t, TenantID(ctx))

	ctx2 := SetTenantID(ctx, "acme")
	assert.Equal(t, "acme", TenantID(ctx2))
	assert.Empty(t, TenantID(ctx))

	ctx3 := SetTenantID(ctx2, "other")
	assert.Equal(t, "other", TenantID(ctx3))
	assert.Equal(t, "acme", TenantID(ctx2))
}

func TestSetIsAdmin_and_IsAdmin(t *testing.T) {
	ctx := context.Background()
	assert.False(t, IsAdmin(ctx))

	ctx2 := SetIsAdmin(ctx, true)
	assert.True(t, IsAdmin(ctx2))
	assert.False(t, IsAdmin(ctx))

	ctx3 := SetIsAdmin(ctx2, false)
	assert.False(t, IsAdmin(ctx3))
	assert.True(t, IsAdmin(ctx2))
}
