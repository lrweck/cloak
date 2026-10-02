// Package auth stands in for whatever package owns the identity. It holds the
// context key, which stays unexported, and exposes a pull function for cloak.
package auth

import (
	"context"
	"log/slog"
)

// Principal is the identity attached to a request.
type Principal struct {
	ID    int
	Email string
}

// key is unexported on purpose. An exported key type would be forgeable by any
// package in the program, which is the collision safety the unexported type buys.
type key struct{}

var principalKey key

// WithPrincipal attaches an identity to the context. Middleware calls this; no
// logging happens here, which is the whole point.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// LogAttrs pulls the identity out for cloak. It lives here rather than at the call
// site because this is the only place the private key is reachable.
//
// Return nil when there is nothing to report, so a missing value is skipped instead
// of being logged as a null.
func LogAttrs(ctx context.Context) []slog.Attr {
	p, ok := ctx.Value(principalKey).(Principal)
	if !ok {
		return nil
	}
	return []slog.Attr{slog.Any("principal", p)}
}
