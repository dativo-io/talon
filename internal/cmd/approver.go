package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/config"
)

var (
	approverName   string
	approverRole   string
	approverTenant string
	approverGroups string
	approverID     string
)

var approverCmd = &cobra.Command{
	Use:   "approver",
	Short: "Manage human approver principals (tenant-scoped) and legacy plan-review approvers",
}

// approverAddCmd creates a TENANT-SCOPED principal with one 256-bit
// credential (#428 minimum for #458). The legacy --role form creates a
// role-only record that legacy plan review accepts but the Action Gateway
// refuses (no tenant scope, 96-bit key).
var approverAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add an approver: --tenant + --groups creates a tenant-scoped principal (action approvals); --role alone creates a legacy plan-review approver",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if err := cfg.EnsureDataDir(); err != nil {
			return err
		}
		store, err := approver.NewStore(cfg.EvidenceDBPath())
		if err != nil {
			return err
		}
		defer store.Close()
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if approverTenant != "" || approverGroups != "" {
			if approverTenant == "" || approverGroups == "" {
				return fmt.Errorf("--tenant and --groups are required together")
			}
			groups := strings.Split(approverGroups, ",")
			token, p, err := store.AddPrincipal(ctx, approverTenant, approverName, groups)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Generated approver credential (shown once, store securely): %s\n", token)
			fmt.Fprintf(cmd.OutOrStdout(), "Principal: %s  Tenant: %s  Subject: %s  Groups: %s  Credential: %s v%d\n",
				p.PrincipalID, p.TenantScope, p.Subject, strings.Join(p.Groups, ","), p.CredentialID, p.CredentialVersion)
			return nil
		}
		if approverRole == "" {
			return fmt.Errorf("provide --tenant and --groups (action approvals) or --role (legacy plan review only)")
		}
		key, rec, err := store.Add(ctx, approverName, approverRole)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Generated LEGACY approver key (store securely): %s\n", key)
		fmt.Fprintf(cmd.OutOrStdout(), "Name: %s  Role: %s  Created: %s\n", rec.Name, rec.Role, rec.CreatedAt.Format(time.RFC3339))
		fmt.Fprintf(cmd.OutOrStdout(), "Note: %s\n", approver.LegacyDisposition)
		return nil
	},
}

var approverListCmd = &cobra.Command{
	Use:   "list",
	Short: "List approver principals and legacy approvers (no secrets)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		store, err := approver.NewStore(cfg.EvidenceDBPath())
		if err != nil {
			return err
		}
		defer store.Close()
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		principals, err := store.ListPrincipals(ctx)
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		fmt.Fprintln(out, "PRINCIPAL\tTENANT\tSUBJECT\tGROUPS\tACTIVE\tCREATED")
		for _, p := range principals {
			fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%t\t%s\n", p.PrincipalID, p.TenantScope, p.Subject, strings.Join(p.Groups, ","), p.Active, p.CreatedAt.Format("2006-01-02"))
		}
		legacy, err := store.List(ctx)
		if err != nil {
			return err
		}
		if len(legacy) > 0 {
			fmt.Fprintf(out, "\nLEGACY approvers — %s\n", approver.LegacyDisposition)
			fmt.Fprintln(out, "NAME\tROLE\tCREATED")
			for _, r := range legacy {
				fmt.Fprintf(out, "%s\t%s\t%s\n", r.Name, r.Role, r.CreatedAt.Format("2006-01-02"))
			}
		}
		return nil
	},
}

var approverRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke an approver principal and all of its credentials",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		store, err := approver.NewStore(cfg.EvidenceDBPath())
		if err != nil {
			return err
		}
		defer store.Close()
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		if err := store.RevokePrincipal(ctx, approverID); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Revoked principal %s\n", approverID)
		return nil
	},
}

var approverRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Issue a new credential version for a principal and revoke the previous one",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		store, err := approver.NewStore(cfg.EvidenceDBPath())
		if err != nil {
			return err
		}
		defer store.Close()
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		token, version, err := store.RotateCredential(ctx, approverID)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Generated approver credential v%d (shown once, store securely): %s\n", version, token)
		return nil
	},
}

var approverDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete LEGACY approvers by role",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		store, err := approver.NewStore(cfg.EvidenceDBPath())
		if err != nil {
			return err
		}
		defer store.Close()
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		return store.DeleteByRole(ctx, approverRole)
	},
}

func init() {
	approverAddCmd.Flags().StringVar(&approverName, "name", "", "Approver display name (subject)")
	approverAddCmd.Flags().StringVar(&approverTenant, "tenant", "", "Tenant scope of the principal (required for action approvals)")
	approverAddCmd.Flags().StringVar(&approverGroups, "groups", "", "Comma-separated approver groups (required with --tenant)")
	approverAddCmd.Flags().StringVar(&approverRole, "role", "", "LEGACY plan-review role (no tenant scope; not accepted for action approvals)")
	_ = approverAddCmd.MarkFlagRequired("name")
	approverRevokeCmd.Flags().StringVar(&approverID, "principal", "", "Principal id to revoke")
	_ = approverRevokeCmd.MarkFlagRequired("principal")
	approverRotateCmd.Flags().StringVar(&approverID, "principal", "", "Principal id to rotate")
	_ = approverRotateCmd.MarkFlagRequired("principal")
	approverDeleteCmd.Flags().StringVar(&approverRole, "role", "", "Legacy role to delete")
	_ = approverDeleteCmd.MarkFlagRequired("role")
	approverCmd.AddCommand(approverAddCmd, approverListCmd, approverRevokeCmd, approverRotateCmd, approverDeleteCmd)
	rootCmd.AddCommand(approverCmd)
}
