package app

import (
	"context"
	"fmt"
	"strconv"
)

// unbindAndDeleteUser makes SDK account deletion an identity operation rather
// than a database-only flag change. If any BOOI server cannot confirm the
// unbind, the SDK row is left untouched so the operation can be retried safely.
func (a *App) unbindAndDeleteUser(ctx context.Context, userID int64, hard bool) error {
	if userID <= 0 {
		return fmt.Errorf("invalid account id")
	}
	openID := strconv.FormatInt(userID, 10)
	if err := a.booi.UnbindRoles(ctx, openID); err != nil {
		return fmt.Errorf("解绑 BOOI 角色失败，SDK 账号未变更: %w", err)
	}
	if hard {
		return a.store.HardDeleteUser(userID)
	}
	return a.store.DeleteUser(userID)
}
