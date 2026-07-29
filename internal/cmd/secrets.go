package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/secrets"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage encrypted secrets vault",
}

var (
	secretsSetTenants []string
	secretsSetAgents  []string
)

var secretsSetCmd = &cobra.Command{
	Use:   "set [name] [value]",
	Short: "Store an encrypted secret",
	Long: `Store an encrypted secret in the vault.

The value may be passed as the second argument, or — preferably — piped on
stdin so the credential never appears in the process list (#310):

  printf '%s' "$OPENAI_API_KEY" | talon secrets set openai-api-key`,
	Args: cobra.RangeArgs(1, 2),
	RunE: secretsSet,
}

var secretsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List secrets (metadata only, values not shown)",
	RunE:  secretsList,
}

var secretsAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View secret access log",
	RunE:  secretsAudit,
}

var secretsRotateCmd = &cobra.Command{
	Use:   "rotate [name]",
	Short: "Re-encrypt a secret with a fresh nonce",
	Args:  cobra.ExactArgs(1),
	RunE:  secretsRotate,
}

var secretsDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Remove a secret from the vault",
	Args:  cobra.ExactArgs(1),
	RunE:  secretsDelete,
}

func init() {
	secretsSetCmd.Flags().StringSliceVar(&secretsSetTenants, "tenant", nil,
		"Restrict retrieval to this tenant (repeatable; glob patterns allowed). Empty means every tenant.")
	secretsSetCmd.Flags().StringSliceVar(&secretsSetAgents, "agent", nil,
		"Restrict retrieval to this agent (repeatable; glob patterns allowed). Empty means every agent.")
	secretsCmd.AddCommand(secretsSetCmd)
	secretsCmd.AddCommand(secretsListCmd)
	secretsCmd.AddCommand(secretsAuditCmd)
	secretsCmd.AddCommand(secretsRotateCmd)
	secretsCmd.AddCommand(secretsDeleteCmd)
	rootCmd.AddCommand(secretsCmd)
}

func openSecretsStore() (*secrets.SecretStore, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}
	cfg.WarnIfDefaultKeys()

	return secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
}

func secretsSet(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	name := args[0]
	var value string
	if len(args) == 2 {
		value = args[1]
	} else {
		v, err := readSecretValueFromStdin(cmd)
		if err != nil {
			return err
		}
		value = v
	}
	if value == "" {
		return fmt.Errorf("secret value is empty")
	}

	store, err := openSecretsStore()
	if err != nil {
		return fmt.Errorf("initializing secrets: %w", err)
	}
	defer store.Close()

	acl := secrets.ACL{Tenants: secretsSetTenants, Agents: secretsSetAgents}
	if err := store.Set(ctx, name, []byte(value), acl); err != nil {
		return fmt.Errorf("storing secret: %w", err)
	}

	fmt.Printf("\u2713 Secret '%s' stored (encrypted at rest)\n", name)
	switch {
	case len(acl.Tenants) == 0 && len(acl.Agents) == 0:
		fmt.Fprintln(cmd.ErrOrStderr(),
			"notice: stored with allow-all ACL \u2014 any tenant's gateway traffic can use this secret; scope with --tenant/--agent for multi-tenant deployments")
	default:
		fmt.Printf("  ACL: tenants=%s agents=%s (empty list = all)\n",
			formatACLList(acl.Tenants), formatACLList(acl.Agents))
	}
	return nil
}

// maxSecretStdinBytes bounds a piped secret value — far above any real
// credential, low enough that a misdirected file redirect fails loudly.
const maxSecretStdinBytes = 1 << 20

// readSecretValueFromStdin reads the secret value from piped stdin (#310), so
// the credential never appears in argv/ps. An interactive terminal with no
// value argument is an explicit error rather than a silent hang waiting for
// input the operator doesn't know to type. Exactly one trailing newline is
// trimmed (echo adds one; printf '%s' does not) — interior whitespace is
// preserved verbatim.
func readSecretValueFromStdin(cmd *cobra.Command) (string, error) {
	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); ok {
		if info, err := f.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			return "", fmt.Errorf("no value argument and stdin is a terminal; pipe the value to keep it out of the process list: printf '%%s' \"$KEY\" | talon secrets set <name>")
		}
	}
	data, err := io.ReadAll(io.LimitReader(in, maxSecretStdinBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading secret value from stdin: %w", err)
	}
	if len(data) > maxSecretStdinBytes {
		return "", fmt.Errorf("stdin value exceeds %d bytes — is this really a secret?", maxSecretStdinBytes)
	}
	s := strings.TrimSuffix(string(data), "\n")
	s = strings.TrimSuffix(s, "\r")
	return s, nil
}

func formatACLList(patterns []string) string {
	if len(patterns) == 0 {
		return "[*]"
	}
	return "[" + strings.Join(patterns, ", ") + "]"
}

func secretsList(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, err := openSecretsStore()
	if err != nil {
		return fmt.Errorf("initializing secrets: %w", err)
	}
	defer store.Close()

	list, err := store.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("listing secrets: %w", err)
	}

	if len(list) == 0 {
		fmt.Println("No secrets stored yet.")
		return nil
	}

	fmt.Println("Secrets (metadata only, values not shown):")
	for i := range list {
		fmt.Printf("  - %s (accessed %d times)\n", list[i].Name, list[i].AccessCount)
	}

	return nil
}

func secretsAudit(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, err := openSecretsStore()
	if err != nil {
		return fmt.Errorf("initializing secrets: %w", err)
	}
	defer store.Close()

	// CLI shows all tenants (tenantID ""); for tenant-scoped use the HTTP API.
	records, err := store.AuditLog(ctx, "", "", 50)
	if err != nil {
		return fmt.Errorf("fetching audit log: %w", err)
	}

	if len(records) == 0 {
		fmt.Println("No secret access records yet.")
		return nil
	}

	fmt.Println("Secret Access Audit Log (last 50):")
	for _, entry := range records {
		status := "\u2713 ALLOWED"
		if !entry.Allowed {
			status = "\u2717 DENIED"
		}
		reason := ""
		if entry.Reason != "" {
			reason = " (" + entry.Reason + ")"
		}
		fmt.Printf("  %s | %s | %s/%s | %s%s\n",
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			status,
			entry.TenantID,
			entry.AgentID,
			entry.SecretName,
			reason,
		)
	}

	return nil
}

func secretsDelete(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	name := args[0]

	store, err := openSecretsStore()
	if err != nil {
		return fmt.Errorf("initializing secrets: %w", err)
	}
	defer store.Close()

	if err := store.Delete(ctx, name); err != nil {
		return fmt.Errorf("deleting secret: %w", err)
	}

	fmt.Printf("✓ Secret '%s' deleted (recorded in access log)\n", name)
	fmt.Fprintln(cmd.ErrOrStderr(),
		"notice: running gateways resolve secrets at request time — traffic referencing this name now fails closed on next use")
	return nil
}

func secretsRotate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	name := args[0]

	store, err := openSecretsStore()
	if err != nil {
		return fmt.Errorf("initializing secrets: %w", err)
	}
	defer store.Close()

	if err := store.Rotate(ctx, name); err != nil {
		return fmt.Errorf("rotating secret: %w", err)
	}

	fmt.Printf("\u2713 Secret '%s' rotated (new nonce generated)\n", name)
	return nil
}
