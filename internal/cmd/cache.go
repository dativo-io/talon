// Package cmd implements talon cache subcommands for the governed semantic cache.
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/cache"
	"github.com/dativo-io/talon/internal/config"
)

var (
	cacheTenantID string
	cacheUserID   string
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage governed semantic cache (stats, list, erase)",
	Long:  "Subcommands for the semantic cache. Cache must be enabled in talon.config.yaml (cache.enabled: true).",
}

var cacheStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show cache statistics (entries per tenant)",
	RunE:  runCacheStats,
}

var cacheListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tenants that have cache entries",
	RunE:  runCacheList,
}

var cacheEraseCmd = &cobra.Command{
	Use:   "erase",
	Short: "GDPR erasure: delete cache entries for a tenant (or tenant+user)",
	Long:  "Delete all cache entries for a tenant (GDPR Article 17). Use --user to erase only entries for a specific user.",
	RunE:  runCacheErase,
}

var cacheConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current cache configuration",
	RunE:  runCacheConfig,
}

func init() {
	cacheCmd.AddCommand(cacheStatsCmd)
	cacheCmd.AddCommand(cacheListCmd)
	cacheCmd.AddCommand(cacheEraseCmd)
	cacheCmd.AddCommand(cacheConfigCmd)
	cacheEraseCmd.Flags().StringVar(&cacheTenantID, "tenant", "", "Tenant ID to erase (required)")
	cacheEraseCmd.Flags().StringVar(&cacheUserID, "user", "", "Optional: erase only entries for this user within the tenant")
	rootCmd.AddCommand(cacheCmd)
}

func openCacheStore() (*cache.Store, *config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	if cfg.Cache == nil || !cfg.Cache.Enabled {
		return nil, cfg, fmt.Errorf("cache is disabled; set cache.enabled: true in talon.config.yaml")
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return nil, nil, fmt.Errorf("creating data directory: %w", err)
	}
	store, err := cache.NewStore(cfg.CacheDBPath(), cfg.SigningKey)
	if err != nil {
		return nil, nil, fmt.Errorf("opening cache store: %w", err)
	}
	return store, cfg, nil
}

func runCacheStats(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, cfg, err := openCacheStore()
	if err != nil {
		return err
	}
	defer store.Close()

	tenants, err := store.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("listing tenants: %w", err)
	}
	fmt.Printf("Cache: %s\n", cfg.CacheDBPath())
	fmt.Printf("Tenants with entries: %d\n\n", len(tenants))
	for _, t := range tenants {
		n, err := store.CountByTenant(ctx, t)
		if err != nil {
			fmt.Printf("  %s: (error: %v)\n", t, err)
			continue
		}
		fmt.Printf("  %s: %d entries\n", t, n)
	}
	return nil
}

func runCacheList(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, _, err := openCacheStore()
	if err != nil {
		return err
	}
	defer store.Close()

	tenants, err := store.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("listing tenants: %w", err)
	}
	for _, t := range tenants {
		fmt.Println(t)
	}
	return nil
}

func runCacheErase(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	if cacheTenantID == "" {
		return fmt.Errorf("--tenant is required for cache erase")
	}

	store, _, err := openCacheStore()
	if err != nil {
		return err
	}
	defer store.Close()

	var n int64
	if cacheUserID != "" {
		n, err = store.EraseTenantUser(ctx, cacheTenantID, cacheUserID)
		if err != nil {
			return fmt.Errorf("erasing cache for tenant %q user %q: %w", cacheTenantID, cacheUserID, err)
		}
		fmt.Printf("\u2713 Erased %d cache entries for tenant %q (user %q)\n", n, cacheTenantID, cacheUserID)
	} else {
		n, err = store.EraseTenant(ctx, cacheTenantID)
		if err != nil {
			return fmt.Errorf("erasing cache for tenant %q: %w", cacheTenantID, err)
		}
		fmt.Printf("\u2713 Erased %d cache entries for tenant %q\n", n, cacheTenantID)
	}
	return nil
}

func runCacheConfig(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.Cache == nil {
		fmt.Println("Cache: not configured (no cache block in talon.config.yaml)")
		return nil
	}
	fmt.Printf("Cache: %s\n", cfg.CacheDBPath())
	fmt.Printf("  enabled: %v\n", cfg.Cache.Enabled)
	fmt.Printf("  default_ttl: %d\n", cfg.Cache.DefaultTTL)
	fmt.Printf("  similarity_threshold: %.2f\n", cfg.Cache.SimilarityThreshold)
	fmt.Printf("  max_entries_per_tenant: %d\n", cfg.Cache.MaxEntriesPerTenant)
	return nil
}
