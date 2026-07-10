// Package wait holds small context-aware timing helpers shared across
// the provider's polling and retry loops.
package wait

import (
	"context"
	"time"
)

// Sleep blocks for d, returning early with the context's error if it is
// cancelled or times out first.
func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
