package store

import (
	"database/sql"
	"errors"
	"time"
)

func (s *Store) migrateLegacyAuthSessions() error {
	now := time.Now().Unix()
	rows, err := s.db.Query(`select id, token, refresh_token, token_expires_at, refresh_token_expires_at,
		token_revoked_at, deleted_at, last_login_at from users`)
	if err != nil {
		return err
	}
	type legacySession struct {
		userID                        int64
		accessToken                   string
		refreshToken                  sql.NullString
		accessExpires, refreshExpires int64
		revokedAt, deletedAt          sql.NullInt64
		lastLoginAt                   int64
	}
	legacy := []legacySession{}
	for rows.Next() {
		var item legacySession
		if err := rows.Scan(&item.userID, &item.accessToken, &item.refreshToken, &item.accessExpires,
			&item.refreshExpires, &item.revokedAt, &item.deletedAt, &item.lastLoginAt); err != nil {
			rows.Close()
			return err
		}
		legacy = append(legacy, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range legacy {
		if item.accessToken == "" || !item.refreshToken.Valid || item.refreshToken.String == "" ||
			item.accessExpires < now || item.refreshExpires < now || item.revokedAt.Valid || item.deletedAt.Valid {
			continue
		}
		var count int
		if err := s.db.QueryRow("select count(*) from auth_sessions where access_token = ? or refresh_token = ?",
			item.accessToken, item.refreshToken.String).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			continue
		}
		if _, err := s.db.Exec(`insert into auth_sessions(id, user_id, access_token, refresh_token,
			access_expires_at, refresh_expires_at, revoked_at, created_at, refreshed_at)
			values (?, ?, ?, ?, ?, ?, null, ?, ?)`, makeToken("as"), item.userID, item.accessToken,
			item.refreshToken.String, item.accessExpires, item.refreshExpires, item.lastLoginAt, item.lastLoginAt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) issueAuthSession(userID int64) (User, error) {
	now := time.Now().Unix()
	access, refresh, accessExpires, refreshExpires := newTokenPair(now)
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`update users set token = ?, refresh_token = ?, token_expires_at = ?,
		refresh_token_expires_at = ?, token_revoked_at = null, last_login_at = ?
		where id = ? and deleted_at is null`, access, refresh, accessExpires, refreshExpires, now, userID)
	if err != nil {
		return User{}, err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return User{}, err
	}
	if updated != 1 {
		return User{}, errors.New("账号不存在")
	}
	if _, err := tx.Exec(`insert into auth_sessions(id, user_id, access_token, refresh_token,
		access_expires_at, refresh_expires_at, revoked_at, created_at, refreshed_at)
		values (?, ?, ?, ?, ?, ?, null, ?, ?)`, makeToken("as"), userID, access, refresh,
		accessExpires, refreshExpires, now, now); err != nil {
		return User{}, err
	}
	u, ok, err := scanUser(tx.QueryRow(`select id, phone, token, refresh_token, password_hash, long_token, deleted_at
		from users where id = ? and deleted_at is null`, userID))
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, errors.New("账号不存在")
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Store) CreateLoginSession(userID int64) (User, error) {
	return s.issueAuthSession(userID)
}

func (s *Store) refreshAuthSession(oldRefresh string) (User, string, error) {
	if oldRefresh == "" {
		return User{}, "", errors.New("缺少刷新凭证")
	}
	now := time.Now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, "", err
	}
	defer tx.Rollback()
	var sessionID string
	var userID int64
	err = tx.QueryRow(`select s.id, s.user_id from auth_sessions s join users u on u.id = s.user_id
		where s.refresh_token = ? and s.revoked_at is null and s.refresh_expires_at >= ?
		and u.deleted_at is null and u.token_revoked_at is null`, oldRefresh, now).Scan(&sessionID, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", errors.New("刷新凭证无效")
	}
	if err != nil {
		return User{}, "", err
	}
	access, refresh, accessExpires, refreshExpires := newTokenPair(now)
	result, err := tx.Exec(`update auth_sessions set access_token = ?, refresh_token = ?,
		access_expires_at = ?, refresh_expires_at = ?, refreshed_at = ?
		where id = ? and refresh_token = ? and revoked_at is null and refresh_expires_at >= ?`,
		access, refresh, accessExpires, refreshExpires, now, sessionID, oldRefresh, now)
	if err != nil {
		return User{}, "", err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return User{}, "", err
	}
	if updated != 1 {
		return User{}, "", errors.New("刷新凭证已被使用")
	}
	if _, err := tx.Exec(`update users set token = ?, refresh_token = ?, token_expires_at = ?,
		refresh_token_expires_at = ?, last_login_at = ? where id = ? and deleted_at is null`,
		access, refresh, accessExpires, refreshExpires, now, userID); err != nil {
		return User{}, "", err
	}
	u, ok, err := scanUser(tx.QueryRow(`select id, phone, ?, ?, password_hash, long_token, deleted_at
		from users where id = ? and deleted_at is null`, access, refresh, userID))
	if err != nil {
		return User{}, "", err
	}
	if !ok {
		return User{}, "", errors.New("账号不存在")
	}
	if err := tx.Commit(); err != nil {
		return User{}, "", err
	}
	return u, access, nil
}

// RevokeSessionByToken revokes one device session without signing other devices out.
func (s *Store) RevokeSessionByToken(token string) error {
	if token == "" {
		return errors.New("缺少登录凭证")
	}
	_, err := s.db.Exec(`update auth_sessions set revoked_at = ?
		where (access_token = ? or refresh_token = ?) and revoked_at is null`, time.Now().Unix(), token, token)
	return err
}
