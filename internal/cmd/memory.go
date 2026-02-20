package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/memory"
)

var (
	memAgent  string
	memTenant string
	memCat    string
	memLimit  int
	memYes    bool
	memVer    int
)

var memoryCmd = &cobra.Command{
	Use:   "memory",
	Short: "Manage agent memory / soul directory",
}

var memoryListCmd = &cobra.Command{
	Use:   "list",
	Short: "List memory entries",
	RunE:  memoryList,
}

var memoryShowCmd = &cobra.Command{
	Use:   "show [entry-id]",
	Short: "Show full memory entry detail",
	Args:  cobra.ExactArgs(1),
	RunE:  memoryShow,
}

var memorySearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Full-text search memory entries",
	Args:  cobra.ExactArgs(1),
	RunE:  memorySearch,
}

var memoryRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Rollback memory to a specific version",
	RunE:  memoryRollback,
}

var memoryHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Show memory health report",
	RunE:  memoryHealth,
}

var memoryAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Show memory audit trail with evidence cross-reference",
	RunE:  memoryAudit,
}

func init() {
	memoryListCmd.Flags().StringVar(&memAgent, "agent", "default", "Agent name")
	memoryListCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")
	memoryListCmd.Flags().StringVar(&memCat, "category", "", "Filter by category")
	memoryListCmd.Flags().IntVar(&memLimit, "limit", 50, "Maximum entries to show")

	memoryShowCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")

	memorySearchCmd.Flags().StringVar(&memAgent, "agent", "default", "Agent name")
	memorySearchCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")
	memorySearchCmd.Flags().IntVar(&memLimit, "limit", 20, "Maximum results")

	memoryRollbackCmd.Flags().StringVar(&memAgent, "agent", "", "Agent name (required)")
	memoryRollbackCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")
	memoryRollbackCmd.Flags().IntVar(&memVer, "to-version", 0, "Version to rollback to (required)")
	memoryRollbackCmd.Flags().BoolVar(&memYes, "yes", false, "Skip confirmation")
	_ = memoryRollbackCmd.MarkFlagRequired("agent")
	_ = memoryRollbackCmd.MarkFlagRequired("to-version")

	memoryHealthCmd.Flags().StringVar(&memAgent, "agent", "", "Agent name (required)")
	memoryHealthCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")
	_ = memoryHealthCmd.MarkFlagRequired("agent")

	memoryAuditCmd.Flags().StringVar(&memAgent, "agent", "default", "Agent name")
	memoryAuditCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")
	memoryAuditCmd.Flags().IntVar(&memLimit, "limit", 20, "Maximum entries")

	memoryCmd.AddCommand(memoryListCmd, memoryShowCmd, memorySearchCmd,
		memoryRollbackCmd, memoryHealthCmd, memoryAuditCmd)
	rootCmd.AddCommand(memoryCmd)
}

func openMemoryStore() (*memory.Store, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}
	return memory.NewStore(cfg.MemoryDBPath())
}

func memoryList(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer store.Close()

	if memCat != "" {
		entries, err := store.List(ctx, memTenant, memAgent, memCat, memLimit)
		if err != nil {
			return fmt.Errorf("listing memory: %w", err)
		}
		if len(entries) == 0 {
			fmt.Println("No memory entries found.")
			return nil
		}
		printEntryTable(entries)
		return nil
	}

	index, err := store.ListIndex(ctx, memTenant, memAgent, memLimit)
	if err != nil {
		return fmt.Errorf("listing memory: %w", err)
	}
	if len(index) == 0 {
		fmt.Println("No memory entries found.")
		return nil
	}
	printIndexTable(index)
	return nil
}

func memoryShow(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer store.Close()

	entry, err := store.Get(ctx, memTenant, args[0])
	if err != nil {
		return fmt.Errorf("getting entry: %w", err)
	}

	fmt.Printf("Memory Entry: %s\n", entry.ID)
	fmt.Printf("  Agent:     %s\n", entry.AgentID)
	fmt.Printf("  Tenant:    %s\n", entry.TenantID)
	fmt.Printf("  Category:  %s\n", entry.Category)
	fmt.Printf("  Type:      %s\n", entry.ObservationType)
	fmt.Printf("  Version:   %d\n", entry.Version)
	fmt.Printf("  Trust:     %d (%s)\n", entry.TrustScore, entry.SourceType)
	fmt.Printf("  Status:    %s\n", entry.ReviewStatus)
	fmt.Printf("  Evidence:  %s\n", entry.EvidenceID)
	fmt.Printf("  Timestamp: %s\n", entry.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	fmt.Println()
	fmt.Printf("  Title: %s\n", entry.Title)
	fmt.Printf("  Content:\n    %s\n", strings.ReplaceAll(entry.Content, "\n", "\n    "))
	fmt.Println()

	if len(entry.FilesAffected) > 0 {
		fmt.Printf("  Files Affected: %s\n", strings.Join(entry.FilesAffected, ", "))
	} else {
		fmt.Printf("  Files Affected: (none)\n")
	}
	if len(entry.ConflictsWith) > 0 {
		fmt.Printf("  Conflicts With: %s\n", strings.Join(entry.ConflictsWith, ", "))
	} else {
		fmt.Printf("  Conflicts With: (none)\n")
	}

	return nil
}

func memorySearch(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer store.Close()

	results, err := store.Search(ctx, memTenant, memAgent, args[0], memLimit)
	if err != nil {
		return fmt.Errorf("searching memory: %w", err)
	}
	if len(results) == 0 {
		fmt.Println("No matches found.")
		return nil
	}
	printIndexTable(results)
	return nil
}

func memoryRollback(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	if !memYes {
		fmt.Printf("Rollback agent %q (tenant: %s) to version %d? [y/N] ", memAgent, memTenant, memVer)
		var confirm string
		_, _ = fmt.Scanln(&confirm)
		if confirm != "y" && confirm != "Y" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	store, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer store.Close()

	if err := store.Rollback(ctx, memTenant, memAgent, memVer); err != nil {
		return fmt.Errorf("rolling back: %w", err)
	}

	fmt.Printf("Rolled back agent %q to version %d.\n", memAgent, memVer)
	return nil
}

func memoryHealth(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer store.Close()

	report, err := store.HealthStats(ctx, memTenant, memAgent)
	if err != nil {
		return fmt.Errorf("getting health stats: %w", err)
	}

	fmt.Printf("Memory Health Report: %s (tenant: %s)\n", memAgent, memTenant)
	fmt.Printf("  Total entries:      %d\n", report.TotalEntries)

	if len(report.TrustDistribution) > 0 {
		var parts []string
		for src, count := range report.TrustDistribution {
			parts = append(parts, fmt.Sprintf("%s(%d)", src, count))
		}
		fmt.Printf("  Trust distribution: %s\n", strings.Join(parts, " "))
	}

	fmt.Printf("  Pending review:     %d\n", report.PendingReview)
	fmt.Printf("  Detected conflicts: %d (%d auto-resolved, %d pending)\n",
		report.ConflictCount, report.AutoResolved, report.PendingConflicts)

	return nil
}

func memoryAudit(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	memStore, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer memStore.Close()

	evStore, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("opening evidence store: %w", err)
	}
	defer evStore.Close()

	entries, err := memStore.AuditLog(ctx, memTenant, memAgent, memLimit)
	if err != nil {
		return fmt.Errorf("querying audit log: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No memory entries found.")
		return nil
	}

	fmt.Printf("Memory Audit Trail: %s (tenant: %s)\n\n", memAgent, memTenant)

	for i := range entries {
		entry := &entries[i]
		fmt.Printf("  %s | %s | %s | trust:%d | %s\n",
			entry.ID,
			entry.Timestamp.Format("2006-01-02 15:04"),
			entry.Category,
			entry.TrustScore,
			entry.ReviewStatus,
		)

		// Cross-reference evidence
		if entry.EvidenceID != "" {
			ev, evErr := evStore.Get(ctx, entry.EvidenceID)
			if evErr != nil {
				fmt.Printf("    Evidence: %s | (not found)\n", entry.EvidenceID)
			} else {
				hmacStatus := "unknown"
				valid, verErr := evStore.Verify(ctx, entry.EvidenceID)
				if verErr == nil {
					if valid {
						hmacStatus = "valid"
					} else {
						hmacStatus = "INVALID"
					}
				}
				fmt.Printf("    Evidence: %s | %s | %s | EUR%.4f | HMAC: %s\n",
					ev.ID, ev.InvocationType, ev.Execution.ModelUsed, ev.Execution.Cost, hmacStatus)
			}
		}

		fmt.Printf("    Source: %s\n", entry.SourceType)

		if len(entry.ConflictsWith) > 0 {
			fmt.Printf("    Conflicts: %s\n", strings.Join(entry.ConflictsWith, ", "))
		}
		fmt.Println()
	}

	return nil
}

func printIndexTable(entries []memory.IndexEntry) {
	fmt.Printf("%-14s | %-18s | %-10s | %-30s | %-5s | %-10s | %s\n",
		"ID", "Category", "Type", "Title", "Trust", "Status", "Timestamp")
	fmt.Println(strings.Repeat("-", 120))
	for i := range entries {
		e := &entries[i]
		title := e.Title
		if len(title) > 30 {
			title = title[:27] + "..."
		}
		fmt.Printf("%-14s | %-18s | %-10s | %-30s | %-5d | %-10s | %s\n",
			e.ID, e.Category, e.ObservationType, title, e.TrustScore,
			e.ReviewStatus, e.Timestamp.Format("2006-01-02 15:04"))
	}
}

func printEntryTable(entries []memory.Entry) {
	fmt.Printf("%-14s | %-18s | %-10s | %-30s | %-5s | %-10s | %s\n",
		"ID", "Category", "Type", "Title", "Trust", "Status", "Timestamp")
	fmt.Println(strings.Repeat("-", 120))
	for i := range entries {
		e := &entries[i]
		title := e.Title
		if len(title) > 30 {
			title = title[:27] + "..."
		}
		fmt.Printf("%-14s | %-18s | %-10s | %-30s | %-5d | %-10s | %s\n",
			e.ID, e.Category, e.ObservationType, title, e.TrustScore,
			e.ReviewStatus, e.Timestamp.Format("2006-01-02 15:04"))
	}
}

// openEvidenceStore is defined in audit.go; we reuse it for the memory audit command.
var _ = openEvidenceStore

// Ensure evidence.Store is referenced for the compiler.
var _ *evidence.Store
