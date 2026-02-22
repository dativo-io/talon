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
