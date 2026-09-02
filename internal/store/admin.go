package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type AdminAccount struct {
	ID             int64  `json:"id"`
	OpenID         string `json:"openid"`
	Phone          string `json:"phone"`
	CreatedAt      int64  `json:"created_at"`
	LastLoginAt    int64  `json:"last_login_at"`
	Cancellation   int    `json:"cancellation_status"`
	CancellationAt int64  `json:"cancellation_at"`
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
		coalesce(cancellation_status, 0), coalesce(cancellation_at, 0)
		from users where deleted_at is null and (? = '' or phone like ? or cast(id as char) like ?)
		order by id desc limit ? offset ?`, query, pattern, pattern, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AdminAccount{}
	for rows.Next() {
		var item AdminAccount
		if err := rows.Scan(&item.ID, &item.Phone, &item.CreatedAt, &item.LastLoginAt, &item.Cancellation, &item.CancellationAt); err != nil {
			return nil, err
		}
		item.OpenID = fmt.Sprintf("%d", item.ID)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) AdminAccountByID(id int64) (AdminAccount, bool, error) {
	var item AdminAccount
	err := s.db.QueryRow(`select id, phone, created_at, last_login_at,
		coalesce(cancellation_status, 0), coalesce(cancellation_at, 0)
		from users where id = ? and deleted_at is null`, id).Scan(
		&item.ID, &item.Phone, &item.CreatedAt, &item.LastLoginAt, &item.Cancellation, &item.CancellationAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminAccount{}, false, nil
	}
	if err != nil {
		return AdminAccount{}, false, err
	}
	item.OpenID = fmt.Sprintf("%d", item.ID)
	return item, true, nil
}

func (s *Store) AdminUpdateAccount(id int64, phone string) error {
	phone, err := normalizeChinaPhone(phone)
	if err != nil {
		return err
	}
	result, err := s.db.Exec("update users set phone = ? where id = ? and deleted_at is null", phone, id)
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
