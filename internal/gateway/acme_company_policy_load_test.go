package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/testutil/acme"
)

// Workstream A, level 3 (configuration): the company action policy is
// operator-owned and lives in talon.config.yaml under
// gateway.organization_policy.constraints. A1-I01 proves the documented
// shape loads through the production loader; A1-U08 proves a malformed
// company key is a load error, never a silently ignored restriction.
func TestACME_A1_I01_CompanyActionPolicy_LoadsFromGatewayConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "talon.config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(acme.CompanyPolicyYAML(1)), 0o600))
	cfg, err := LoadGatewayConfig(path)
	require.NoError(t, err, "the company action policy shape must load")
	require.Equal(t, []string{acme.DeleteAction}, cfg.OrganizationPolicy.Constraints.ForbiddenTools)
}

func TestACME_A1_U08_MalformedCompanyActionPolicy_IsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "talon.config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(acme.CompanyPolicyYAMLMalformed), 0o600))
	_, err := LoadGatewayConfig(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rulez", "the error must name the unknown company-policy key")
}
