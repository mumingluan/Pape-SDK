package store

import (
	"database/sql"
	"errors"
	"net/mail"
	"strings"
	"time"
)

func NormalizeAccount(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "@") {
		value = strings.ToLower(value)
		address, err := mail.ParseAddress(value)
		if err != nil || address.Address != value || len(value) > 254 || strings.ContainsAny(value, "\r\n") {
			return "", errors.New("请输入正确的邮箱地址")
		}
		return value, nil
	}
	if !chinaMobilePattern.MatchString(value) {
		return "", errors.New("请输入正确的中国大陆手机号或邮箱")
	}
	return value, nil
}
func (s *Store) initBindings() error {
	if s.driver != "sqlite" {
		return errors.New("account bindings require SQLite")
	}
	rows, err := s.db.Query("pragma table_info(users)")
	if err != nil {
		return err
	}
	exists := false
	for rows.Next() {
		var cid, nn, pk int
		var name, typ string
		var def any
		if err := rows.Scan(&cid, &name, &typ, &nn, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "email" {
			exists = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !exists {
		if _, err = s.db.Exec("alter table users add column email text"); err != nil {
			return err
		}
	}
	if _, err = s.db.Exec("update users set email=lower(phone) where phone like '%@%' and deleted_at is null and email is null"); err != nil {
		return err
	}
	_, err = s.db.Exec("create unique index if not exists users_email_unique on users(email) where email is not null and email <> ''")
	return err
}
func (s *Store) AccountBindings(u User) (string, string) {
	var email sql.NullString
	_ = s.db.QueryRow("select email from users where id = ?", u.ID).Scan(&email)
	if strings.Contains(u.Phone, "@") {
		return "", strings.SplitN(u.Phone, "#deleted#", 2)[0]
	}
	return u.Phone, email.String
}
func validateBindings(phone, email string) (string, string, error) {
	phone, email = strings.TrimSpace(phone), strings.TrimSpace(email)
	if phone == "" && email == "" {
		return "", "", errors.New("手机号和邮箱至少保留一个")
	}
	if phone != "" && !chinaMobilePattern.MatchString(phone) {
		return "", "", errors.New("请输入正确的中国大陆手机号")
	}
	if email != "" {
		var err error
		email, err = NormalizeAccount(email)
		if err != nil || !strings.Contains(email, "@") {
			return "", "", errors.New("请输入正确的邮箱地址")
		}
	}
	return phone, email, nil
}

// One write transaction serializes binding changes, including simultaneous unbinds.
func (s *Store) UpdateBindings(id int64, phone, email *string) error {
	return s.updateBindings(id, phone, email, "", "")
}

func (s *Store) UnbindVerified(id int64, kind, retained string) error {
	empty := ""
	if kind == "phone" {
		return s.updateBindings(id, &empty, nil, kind, retained)
	}
	if kind == "email" {
		return s.updateBindings(id, nil, &empty, kind, retained)
	}
	return errors.New("invalid binding kind")
}

func (s *Store) updateBindings(id int64, phone, email *string, kind, retained string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec("update users set security_changed_at = security_changed_at where id = ? and deleted_at is null", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("账号不存在")
	}
	var primary string
	var secondary sql.NullString
	if err = tx.QueryRow("select phone,email from users where id = ?", id).Scan(&primary, &secondary); err != nil {
		return err
	}
	currentPhone, currentEmail := primary, secondary.String
	if strings.Contains(primary, "@") {
		currentPhone, currentEmail = "", primary
	}
	if kind == "phone" && currentEmail != retained || kind == "email" && currentPhone != retained {
		return errors.New("绑定信息已变更，请重新验证")
	}
	if phone != nil {
		currentPhone = *phone
	}
	if email != nil {
		currentEmail = *email
	}
	currentPhone, currentEmail, err = validateBindings(currentPhone, currentEmail)
	if err != nil {
		return err
	}
	primary = currentPhone
	if primary == "" {
		primary = currentEmail
	}
	var emailValue any
	if currentEmail != "" {
		emailValue = currentEmail
	}
	_, err = tx.Exec("update users set phone=?,email=?,security_changed_at=?,security_override=null where id=?", primary, emailValue, time.Now().Unix(), id)
	if err != nil {
		if isUniqueConstraint(err) {
			return errors.New("手机号或邮箱已被其他账号绑定")
		}
		return err
	}
	return tx.Commit()
}
func (s *Store) CreateAccount(phone, email, hash string) (User, error) {
	phone, email, err := validateBindings(phone, email)
	if err != nil {
		return User{}, err
	}
	primary := phone
	if primary == "" {
		primary = email
	}
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var emailValue any
	if email != "" {
		emailValue = email
	}
	now := time.Now().Unix()
	result, err := tx.Exec("insert into users(phone,email,password_hash,token,refresh_token,token_expires_at,refresh_token_expires_at,token_revoked_at,created_at,last_login_at) values(?,?,?,'',null,0,0,0,?,?)", primary, emailValue, hash, now, now)
	if err != nil {
		if isUniqueConstraint(err) {
			return User{}, errors.New("手机号或邮箱已被其他账号绑定")
		}
		return User{}, err
	}
	_, err = result.LastInsertId()
	if err != nil {
		return User{}, err
	}
	if err = tx.Commit(); err != nil {
		return User{}, err
	}
	u, _, err := s.userByPhone(primary)
	return u, err
}
