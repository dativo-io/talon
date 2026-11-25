package console

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

// BenchmarkUseCasesList measures what the use-case statuses (#575) add to
// the AI Use Cases list: "rows" is the list's existing reads (the fleet
// projection over one agent scan, and the runtime records), "statuses" the
// section the list now adds over the rows' scan. Each use case has 20
// gateway records over the last 10 days, its newest one under the current
// policy, and a running gateway reports every use case loaded.
//
//	go test ./internal/console -run '^$' -bench BenchmarkUseCasesList -benchtime 20x
func BenchmarkUseCasesList(b *testing.B) {
	for _, n := range []int{10, 100} {
		b.Run(fmt.Sprintf("use_cases=%d", n), func(b *testing.B) {
			f := newStatusFixture(b)
			names := make([]string, n)
			for i := range names {
				names[i] = fmt.Sprintf("app-%03d", i)
				f.writeAgent(b, names[i], "policies:\n  cost_limits:\n    monthly: 1000\n")
			}
			ctx := context.Background()
			for _, name := range names {
				agent, eff := f.digests(b, name)
				for k := 0; k < 20; k++ {
					ev := &evidence.Evidence{
						ID: fmt.Sprintf("%s-%02d", name, k), CorrelationID: fmt.Sprintf("c-%s-%02d", name, k), TenantID: "default", AgentID: name,
						InvocationType: "gateway", Timestamp: f.now.Add(-time.Duration(k) * 12 * time.Hour),
						PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow"},
						Execution:       evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.01, Currency: "USD", PricingKnown: true},
						RoutingDecision: &evidence.RoutingDecision{SelectedProvider: "openai"},
					}
					if k == 0 {
						ev.PolicyDecision.PolicyDigests = &evidence.PolicyDigests{Agent: agent, Effective: eff}
					}
					if err := f.writer.Store(ctx, ev); err != nil {
						b.Fatal(err)
					}
				}
			}
			f.gatewayRuns(b, append(names, "support-bot", "fresh-bot")...)
			uc, scan := f.svc.useCasesAndScan(ctx, "")
			b.Run("rows", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_ = f.svc.useCases(ctx, "")
				}
			})
			b.Run("statuses", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					st := f.svc.useCaseStatuses(ctx, uc.Rows, uc.Runtime, scan)
					if len(st.Items) != n+2 || st.Items[0].Code == "" {
						b.Fatalf("statuses: %+v", st)
					}
				}
			})
		})
	}
}
