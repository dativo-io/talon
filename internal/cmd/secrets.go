package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/secrets"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage encrypted secrets vault",
}

var secretsSetCmd = &cobra.Command{
	Use:   "set [name] [value]",
	Short: "Store an encrypted secret",
	Args:  cobra.ExactArgs(2),
	RunE:  secretsSet,
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

func init() {
	secretsCmd.AddCommand(secretsSetCmd)
	secretsCmd.AddCommand(secretsListCmd)
	secretsCmd.AddCommand(secretsAuditCmd)
	secretsCmd.AddCommand(secretsRotateCmd)
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
	value := args[1]

	store, err := openSecretsStore()
	if err != nil {
		return fmt.Errorf("initializing secrets: %w", err)
	}
	defer store.Close()

	acl := secrets.ACL{}
	if err := store.Set(ctx, name, []byte(value), acl); err != nil {
		return fmt.Errorf("storing secret: %w", err)
	}

	fmt.Printf("\u2713 Secret '%s' stored (encrypted at rest)\n", name)
	return nil
}

func secretsList(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, err := openSecretsStore()
	if err != nil {
		return fmt.Errorf("initializing secrets: %w", err)
	}
	defer store.Close()

	list, err := store.List(ctx, "*")
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

	records, err := store.AuditLog(ctx, "", 50)
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
