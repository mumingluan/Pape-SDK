package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const accountSecurityWindow = 14 * 24 * time.Hour

type AdminAccount struct {
	ID                int64  `json:"id"`
	OpenID            string `json:"openid"`
	Phone             string `json:"phone"`
	CreatedAt         int64  `json:"created_at"`
	LastLoginAt       int64  `json:"last_login_at"`
	Cancellation      int    `json:"cancellation_status"`
	CancellationAt    int64  `json:"cancellation_at"`
	DeletedAt         int64  `json:"deleted_at"`
	SecurityChangedAt int64  `json:"security_changed_at"`
	SecurityOverride  *bool  `json:"security_override"`
	IsSafe            bool   `json:"is_safe"`
}

func (s *Store) AdminAccounts(query string, limit, offset int) ([]AdminAccount, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	query = strings.TrimSpace(query)
	pattern := "%" + query + "%"
	rows, err := s.db.Query(`select id, phone, created_at, last_login_at,
		coalesce(cancellation_status, 0), coalesce(cancellation_at, 0), coalesce(deleted_at, 0),
		coalesce(security_changed_at, 0), security_override
		from users where (? = '' or phone like ? or cast(id as char) like ?)
		order by id desc limit ? offset ?`, query, pattern, pattern, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AdminAccount{}
	for rows.Next() {
		var item AdminAccount
		var override sql.NullInt64
		if err := rows.Scan(&item.ID, &item.Phone, &item.CreatedAt, &item.LastLoginAt, &item.Cancellation, &item.CancellationAt, &item.DeletedAt, &item.SecurityChangedAt, &override); err != nil {
			return nil, err
		}
		item.OpenID = fmt.Sprintf("%d", item.ID)
		applySecurityStatus(&item, override)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) AdminAccountByID(id int64) (AdminAccount, bool, error) {
	var item AdminAccount
	var override sql.NullInt64
	err := s.db.QueryRow(`select id, phone, created_at, last_login_at,
		coalesce(cancellation_status, 0), coalesce(cancellation_at, 0), coalesce(deleted_at, 0),
		coalesce(security_changed_at, 0), security_override
		from users where id = ?`, id).Scan(
		&item.ID, &item.Phone, &item.CreatedAt, &item.LastLoginAt, &item.Cancellation, &item.CancellationAt, &item.DeletedAt,
		&item.SecurityChangedAt, &override,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminAccount{}, false, nil
	}
	if err != nil {
		return AdminAccount{}, false, err
	}
	item.OpenID = fmt.Sprintf("%d", item.ID)
	applySecurityStatus(&item, override)
	return item, true, nil
}

func applySecurityStatus(item *AdminAccount, override sql.NullInt64) {
	if override.Valid {
		value := override.Int64 != 0
		item.SecurityOverride = &value
		item.IsSafe = value
		return
	}
	item.IsSafe = item.SecurityChangedAt == 0 || item.SecurityChangedAt <= time.Now().Add(-accountSecurityWindow).Unix()
}

func (s *Store) UserSafeStatus(id int64) (bool, error) {
	var changedAt int64
	var override sql.NullInt64
	if err := s.db.QueryRow("select coalesce(security_changed_at, 0), security_override from users where id = ? and deleted_at is null", id).Scan(&changedAt, &override); err != nil {
		return false, err
	}
	item := AdminAccount{SecurityChangedAt: changedAt}
	applySecurityStatus(&item, override)
	return item.IsSafe, nil
}

func (s *Store) SetSecurityOverride(id int64, safe bool) error {
	value := 0
	if safe {
		value = 1
	}
	result, err := s.db.Exec("update users set security_override = ? where id = ?", value, id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("账号不存在")
	}
	return nil
}

func (s *Store) AdminUpdateAccount(id int64, phone string) error {
	phone, err := normalizeChinaPhone(phone)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	result, err := s.db.Exec(`update users set
		security_changed_at = case when phone <> ? then ? else security_changed_at end,
		security_override = case when phone <> ? then null else security_override end,
		phone = ? where id = ?`, phone, now, phone, phone, id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("账号不存在")
	}
	return nil
}

func (s *Store) RestoreUser(id int64, phone string) error {
	var current string
	if err := s.db.QueryRow("select phone from users where id = ?", id).Scan(&current); err != nil {
		return err
	}
	phone = strings.TrimSpace(phone)
	if phone == "" {
		phone = strings.SplitN(current, "#deleted#", 2)[0]
	}
	phone, err := normalizeChinaPhone(phone)
	if err != nil {
		return err
	}
	result, err := s.db.Exec(`update users set phone = ?, cancellation_status = 1,
		cancellation_at = null, deleted_at = null, security_changed_at = ?, security_override = null where id = ?`, phone, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("账号不存在")
	}
	return nil
}

func (s *Store) HardDeleteUser(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("delete from comet_sessions where user_id = ?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("delete from auth_sessions where user_id = ?", id); err != nil {
		return err
	}
	result, err := tx.Exec("delete from users where id = ?", id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("账号不存在")
	}
	return tx.Commit()
}
