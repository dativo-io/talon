package gateway

import "context"

type quickstartCallerCtxKey struct{}

// WithQuickstartCaller attaches a trusted synthetic quickstart caller to the request context.
func WithQuickstartCaller(ctx context.Context, caller *CallerConfig) context.Context {
	return context.WithValue(ctx, quickstartCallerCtxKey{}, caller)
}

// QuickstartCallerFromContext returns the synthetic quickstart caller when present.
func QuickstartCallerFromContext(ctx context.Context) *CallerConfig {
	v := ctx.Value(quickstartCallerCtxKey{})
	caller, _ := v.(*CallerConfig)
	return caller
}
