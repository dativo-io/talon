package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
)

var (
	memAgent  string
	memTenant string
	memCat    string
	memLimit  int
	memYes    bool
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
	Use:   "rollback <mem_id>",
	Short: "Rollback memory to a specific entry (soft-delete newer entries for audit)",
	Args:  cobra.ExactArgs(1),
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

var memoryAsOfCmd = &cobra.Command{
	Use:   "as-of <RFC3339 timestamp>",
	Short: "List memory entries valid at a point in time (compliance: NIS2, EU AI Act)",
	Args:  cobra.ExactArgs(1),
	RunE:  memoryAsOf,
}

func init() {
	memoryListCmd.Flags().StringVar(&memAgent, "agent", "", "Agent name (from agent.talon.yaml in cwd if unset)")
	memoryListCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")
	memoryListCmd.Flags().StringVar(&memCat, "category", "", "Filter by category")
	memoryListCmd.Flags().IntVar(&memLimit, "limit", 50, "Maximum entries to show")

	memoryShowCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")

	memorySearchCmd.Flags().StringVar(&memAgent, "agent", "", "Agent name (from agent.talon.yaml in cwd if unset)")
	memorySearchCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")
	memorySearchCmd.Flags().IntVar(&memLimit, "limit", 20, "Maximum results")

	memoryRollbackCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")
	memoryRollbackCmd.Flags().BoolVar(&memYes, "yes", false, "Skip confirmation")

	memoryHealthCmd.Flags().StringVar(&memAgent, "agent", "", "Agent name (from agent.talon.yaml in cwd if unset)")
	memoryHealthCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")

	memoryAuditCmd.Flags().StringVar(&memAgent, "agent", "", "Agent name (from agent.talon.yaml in cwd if unset)")
	memoryAuditCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")
	memoryAuditCmd.Flags().IntVar(&memLimit, "limit", 20, "Maximum entries")

	memoryAsOfCmd.Flags().StringVar(&memAgent, "agent", "", "Agent name (from agent.talon.yaml in cwd if unset)")
	memoryAsOfCmd.Flags().StringVar(&memTenant, "tenant", "default", "Tenant ID")
	memoryAsOfCmd.Flags().IntVar(&memLimit, "limit", 50, "Maximum entries")

	memoryCmd.AddCommand(memoryListCmd, memoryShowCmd, memorySearchCmd,
		memoryRollbackCmd, memoryHealthCmd, memoryAuditCmd, memoryAsOfCmd)
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

// resolveMemoryAgent returns the agent name to use for memory commands. When memAgent is
// non-empty (--agent set), that value is used. Otherwise, if agent.talon.yaml (or the
// configured default policy) exists in the current directory, the agent name is read from
// it so commands never fall back to "default" when running inside a project. If no policy
// is found or it has no agent name, returns ("default", false). Second return is true when
// the name came from a policy file.
func resolveMemoryAgent(ctx context.Context) (agent string, fromPolicy bool) {
	cfg, err := config.Load()
	if err != nil {
		return "default", false
	}
	return resolveMemoryAgentFromPolicy(ctx, memAgent, ".", cfg.DefaultPolicy)
}

// resolveMemoryAgentFromPolicy resolves the effective agent name from an explicit value or
// by loading the policy file under baseDir. Used by memory commands and by tests. When
// explicitAgent is non-empty it is returned with fromPolicy true. Otherwise the policy at
// baseDir+policyPath is loaded and pol.Agent.Name is returned if set; if not, returns
// ("default", false).
func resolveMemoryAgentFromPolicy(ctx context.Context, explicitAgent, baseDir, policyPath string) (agent string, fromPolicy bool) {
	if explicitAgent != "" {
		return explicitAgent, true
	}
	safePath, err := policy.ResolvePathUnderBase(baseDir, policyPath)
	if err != nil {
		return "default", false
	}
	if _, err := os.Stat(safePath); err != nil {
		return "default", false
	}
	pol, err := policy.LoadPolicy(ctx, safePath, false, baseDir)
	if err != nil {
		return "default", false
	}
	if pol.Agent.Name == "" {
		return "default", false
	}
	return pol.Agent.Name, true
}

func memoryList(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	agent, _ := resolveMemoryAgent(ctx)

	store, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer store.Close()

	if memCat != "" {
		entries, err := store.List(ctx, memTenant, agent, memCat, memLimit)
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

	index, err := store.ListIndex(ctx, memTenant, agent, memLimit)
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
	fmt.Printf("  Trust:     %d (%s)\n", entry.TrustScore, entry.SourceType)
	fmt.Printf("  Status:    %s\n", entry.ReviewStatus)
	if entry.ConsolidationStatus != "" && entry.ConsolidationStatus != "active" {
		fmt.Printf("  State:     %s\n", strings.ToUpper(entry.ConsolidationStatus))
	}
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

	agent, _ := resolveMemoryAgent(ctx)

	store, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer store.Close()
	results, err := store.Search(ctx, memTenant, agent, args[0], memLimit)
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

	entryID := args[0]

	store, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer store.Close()

	entry, err := store.Get(ctx, memTenant, entryID)
	if err != nil {
		return fmt.Errorf("entry not found: %w", err)
	}

	if !memYes {
		fmt.Printf("Rollback agent %q (tenant: %s) to entry %s? All newer entries will be marked as rolled back.\n",
			entry.AgentID, memTenant, entryID)
		fmt.Printf("  Entry: %s | %s | %s\n", entry.ID, entry.Category, entry.Title)
		fmt.Print("Proceed? [y/N] ")
		var confirm string
		_, _ = fmt.Scanln(&confirm)
		if confirm != "y" && confirm != "Y" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	affected, err := store.RollbackTo(ctx, memTenant, entryID)
	if err != nil {
		return fmt.Errorf("rolling back: %w", err)
	}

	fmt.Printf("Rolled back agent %q to entry %s (%d entries marked as rolled_back).\n",
		entry.AgentID, entryID, affected)
	return nil
}

func memoryHealth(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	agent, fromPolicy := resolveMemoryAgent(ctx)
	if agent == "" || (!fromPolicy && agent == "default") {
		return fmt.Errorf("agent name required: set --agent or run from a directory containing %s", config.DefaultPolicy)
	}

	store, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer store.Close()

	report, err := store.HealthStats(ctx, memTenant, agent)
	if err != nil {
		return fmt.Errorf("getting health stats: %w", err)
	}

	fmt.Printf("Memory Health Report: agent %s, tenant %s\n", agent, memTenant)
	fmt.Printf("  Active entries:     %d\n", report.TotalEntries)
	if report.RolledBack > 0 {
		fmt.Printf("  Rolled back:        %d\n", report.RolledBack)
	}

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

	agent, _ := resolveMemoryAgent(ctx)

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

	entries, err := memStore.AuditLog(ctx, memTenant, agent, memLimit)
	if err != nil {
		return fmt.Errorf("querying audit log: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No memory entries found.")
		return nil
	}

	fmt.Printf("Memory Audit Trail: agent %s, tenant %s\n\n", agent, memTenant)

	for i := range entries {
		entry := &entries[i]
		status := entry.ReviewStatus
		switch entry.ConsolidationStatus {
		case "rolled_back":
			status = "ROLLED_BACK"
		case "invalidated":
			status = "INVALIDATED"
		}
		fmt.Printf("  %s | %s | %s | trust:%d | %s\n",
			entry.ID,
			entry.Timestamp.Format("2006-01-02 15:04"),
			entry.Category,
			entry.TrustScore,
			status,
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

func memoryAsOf(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	asOf, err := time.Parse(time.RFC3339, args[0])
	if err != nil {
		return fmt.Errorf("parsing as-of time (use RFC3339, e.g. 2026-02-23T12:00:00Z): %w", err)
	}

	agent, _ := resolveMemoryAgent(ctx)

	store, err := openMemoryStore()
	if err != nil {
		return fmt.Errorf("opening memory store: %w", err)
	}
	defer store.Close()

	entries, err := store.AsOf(ctx, memTenant, agent, asOf, memLimit)
	if err != nil {
		return fmt.Errorf("querying memory as-of %s: %w", asOf.Format(time.RFC3339), err)
	}
	if len(entries) == 0 {
		fmt.Printf("No memory entries valid at %s.\n", asOf.Format(time.RFC3339))
		return nil
	}
	fmt.Printf("Memory entries valid at %s (tenant: %s, agent: %s):\n\n", asOf.Format(time.RFC3339), memTenant, agent)
	printEntryTable(entries)
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
