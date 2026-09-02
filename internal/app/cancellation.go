package app

import (
	"context"
	"log"
	"time"
)

const cancellationFinalizerInterval = time.Minute

// runCancellationFinalizer completes applications only after the official
// 15-day cooling-off period. A failed BOOI leaves the SDK account untouched so
// the next pass can retry safely.
func (a *App) runCancellationFinalizer() {
	a.finalizeDueCancellations(context.Background())
	ticker := time.NewTicker(cancellationFinalizerInterval)
	defer ticker.Stop()
	for range ticker.C {
		a.finalizeDueCancellations(context.Background())
	}
}

func (a *App) finalizeDueCancellations(ctx context.Context) {
	if a.store == nil {
		return
	}
	now := time.Now().Unix()
	items, err := a.store.DueCancellations(now, 100)
	if err != nil {
		log.Printf("[sdk-cancellation] list due cancellations: %v", err)
		return
	}
	for _, item := range items {
		if err := a.booi.UnbindRoles(ctx, item.OpenID); err != nil {
			log.Printf("[sdk-cancellation] waiting for every BOOI before completing account cancellation openid=%q: %v", item.OpenID, err)
			continue
		}
		completed, err := a.store.CompleteCancellation(item.UserID, now)
		if err != nil {
			log.Printf("[sdk-cancellation] complete account cancellation user_id=%d: %v", item.UserID, err)
			continue
		}
		if completed {
			log.Printf("[sdk-cancellation] account cancellation completed user_id=%d openid=%q", item.UserID, item.OpenID)
		}
	}
}
