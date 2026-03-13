package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/config"
)

var (
	approverName string
	approverRole string
)

var approverCmd = &cobra.Command{
	Use:   "approver",
	Short: "Manage plan approver identities",
}

var approverAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add approver and generate bearer key",
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
		key, rec, err := store.Add(ctx, approverName, approverRole)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Generated approver key (store securely): %s\n", key)
		fmt.Fprintf(cmd.OutOrStdout(), "Name: %s  Role: %s  Created: %s\n", rec.Name, rec.Role, rec.CreatedAt.Format(time.RFC3339))
		return nil
	},
}

var approverListCmd = &cobra.Command{
	Use:   "list",
	Short: "List approvers",
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
		list, err := store.List(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "NAME\tROLE\tCREATED")
		for _, r := range list {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", r.Name, r.Role, r.CreatedAt.Format("2006-01-02"))
		}
		return nil
	},
}

var approverDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete approvers by role",
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
	approverAddCmd.Flags().StringVar(&approverName, "name", "", "Approver display name")
	approverAddCmd.Flags().StringVar(&approverRole, "role", "", "Approver role")
	_ = approverAddCmd.MarkFlagRequired("name")
	_ = approverAddCmd.MarkFlagRequired("role")
	approverDeleteCmd.Flags().StringVar(&approverRole, "role", "", "Role to delete")
	_ = approverDeleteCmd.MarkFlagRequired("role")
	approverCmd.AddCommand(approverAddCmd, approverListCmd, approverDeleteCmd)
	rootCmd.AddCommand(approverCmd)
}
