package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

type Store struct {
	db     *sql.DB
	driver string
}

type User struct {
	ID           int64
	Phone        string
	OpenID       string
	NID          int64
	Token        string
	RefreshToken sql.NullString
	PasswordHash sql.NullString
	LongToken    sql.NullString
	DeletedAt    sql.NullInt64
}

var chinaMobilePattern = regexp.MustCompile(`^1[3-9][0-9]{9}$`)

func normalizeChinaPhone(phone string) (string, error) {
	phone = strings.TrimSpace(phone)
	if !chinaMobilePattern.MatchString(phone) {
		return "", errors.New("请输入正确的中国大陆手机号")
	}
	return phone, nil
}

func Open(dbURI, baseDir string) (*Store, error) {
	driver, dsn, err := parseURI(dbURI, baseDir)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if driver == "sqlite" {
		if err := os.MkdirAll(filepath.Dir(dsn), 0o755); err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		_, _ = db.Exec("pragma journal_mode = wal")
		_, _ = db.Exec("pragma busy_timeout = 5000")
	}
	s := &Store{db: db, driver: driver}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func parseURI(dbURI, baseDir string) (string, string, error) {
	if strings.HasPrefix(dbURI, "sqlite://") {
		p := strings.TrimPrefix(dbURI, "sqlite://")
		if !filepath.IsAbs(p) {
			p = filepath.Join(baseDir, p)
		}
		return "sqlite", p, nil
	}
	if strings.HasPrefix(dbURI, "mysql://") {
		u, err := url.Parse(dbURI)
		if err != nil {
			return "", "", err
		}
		user := u.User.Username()
		pass, _ := u.User.Password()
		host := u.Host
		dbname := strings.TrimPrefix(u.Path, "/")
		query := u.RawQuery
		dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", user, pass, host, dbname)
		if query != "" {
			dsn += "?" + query
		}
		return "mysql", dsn, nil
	}
	return "", "", errors.New("db_uri must start with sqlite:// or mysql://")
}

func (s *Store) init() error {
	if s.driver == "mysql" {
		_, err := s.db.Exec(`
create table if not exists users (
	id bigint primary key auto_increment,
	phone varchar(64) unique not null,
	openid varchar(64) unique not null,
	nid bigint unique not null,
	token varchar(128) not null,
	refresh_token varchar(128),
	long_token text,
	password_hash text,
	deleted_at bigint,
	created_at bigint not null,
	last_login_at bigint not null
);
create table if not exists sms_codes (
	phone varchar(64) primary key,
	code varchar(16) not null,
	expires_at bigint not null
);
create table if not exists sms_verifications (
	id bigint primary key auto_increment,
	phone varchar(64) not null,
	scene varchar(64) not null,
	code varchar(16) not null,
	ip varchar(64) not null,
	created_at bigint not null,
	expires_at bigint not null,
	consumed_at bigint,
	index idx_sms_verifications_phone_scene(phone, scene, created_at)
);
create table if not exists sms_events (
	id bigint primary key auto_increment,
	phone varchar(64) not null,
	ip varchar(64) not null,
	created_at bigint not null,
	index idx_sms_events_phone_created(phone, created_at),
	index idx_sms_events_ip_created(ip, created_at)
);
create table if not exists comet_sessions (
	id varchar(64) primary key,
	user_id bigint not null,
	token varchar(128) not null,
	created_at bigint not null
);
create table if not exists request_log (
	id bigint primary key auto_increment,
	created_at bigint not null,
	method varchar(16) not null,
	host varchar(255) not null,
	path varchar(512) not null,
	body_bytes bigint not null
);`)
		if err != nil {
			return err
		}
		if err := s.ensureColumns(); err != nil {
			return err
		}
		return nil
	}
	_, err := s.db.Exec(`
create table if not exists users (
	id integer primary key autoincrement,
	phone varchar(64) unique not null,
	openid varchar(64) unique not null,
	nid bigint unique not null,
	token varchar(128) not null,
	refresh_token varchar(128),
	long_token text,
	password_hash text,
	deleted_at bigint,
	created_at bigint not null,
	last_login_at bigint not null
);
create table if not exists sms_codes (
	phone varchar(64) primary key,
	code varchar(16) not null,
	expires_at bigint not null
);
create table if not exists sms_verifications (
	id integer primary key autoincrement,
	phone varchar(64) not null,
	scene varchar(64) not null,
	code varchar(16) not null,
	ip varchar(64) not null,
	created_at bigint not null,
	expires_at bigint not null,
	consumed_at bigint
);
create index if not exists idx_sms_verifications_phone_scene on sms_verifications(phone, scene, created_at);
create table if not exists sms_events (
	id integer primary key autoincrement,
	phone varchar(64) not null,
	ip varchar(64) not null,
	created_at bigint not null
);
create index if not exists idx_sms_events_phone_created on sms_events(phone, created_at);
create index if not exists idx_sms_events_ip_created on sms_events(ip, created_at);
create table if not exists comet_sessions (
	id varchar(64) primary key,
	user_id bigint not null,
	token varchar(128) not null,
	created_at bigint not null
);
create table if not exists request_log (
	id integer primary key autoincrement,
	created_at bigint not null,
	method varchar(16) not null,
	host varchar(255) not null,
	path varchar(512) not null,
	body_bytes bigint not null
);`)
	if err != nil {
		return err
	}
	if err := s.ensureColumns(); err != nil {
		return err
	}
	return nil
}

func (s *Store) LogRequest(method, host, path string, bodyBytes int64) {
	_, _ = s.db.Exec("insert into request_log(created_at, method, host, path, body_bytes) values (?, ?, ?, ?, ?)", time.Now().Unix(), method, host, path, bodyBytes)
}

func (s *Store) ensureColumns() error {
	for name, definition := range map[string]string{
		"password_hash": "text",
		"refresh_token": "varchar(128)",
		"deleted_at":    "bigint",
	} {
		if _, err := s.db.Exec("alter table users add column " + name + " " + definition); err != nil && !isDuplicateColumn(err) {
			return err
		}
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists")
}

func (s *Store) CheckSMSRate(phone, ip string) error {
	var err error
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-60 * time.Second).Unix()
	var phoneCount int
	if err := s.db.QueryRow("select count(*) from sms_events where phone = ? and created_at >= ?", phone, cutoff).Scan(&phoneCount); err != nil {
		return err
	}
	if phoneCount >= 1 {
		return errors.New("验证码发送过于频繁，请稍后再试")
	}
	var ipCount int
	if err := s.db.QueryRow("select count(*) from sms_events where ip = ? and created_at >= ?", ip, cutoff).Scan(&ipCount); err != nil {
		return err
	}
	if ipCount >= 10 {
		return errors.New("验证码发送次数过多，请稍后再试")
	}
	return nil
}

func (s *Store) IssueSMS(phone, scene, code, ip string) error {
	if err := s.insertSMS(phone, scene, code, ip); err != nil {
		return err
	}
	_, err := s.db.Exec("insert into sms_events(phone, ip, created_at) values (?, ?, ?)", phone, ip, time.Now().Unix())
	return err
}

func (s *Store) MirrorSMS(phone, scene, code, ip string) error {
	return s.insertSMS(phone, scene, code, ip)
}

func (s *Store) insertSMS(phone, scene, code, ip string) error {
	var err error
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		return err
	}
	if scene == "" {
		return errors.New("缺少验证码用途")
	}
	now := time.Now().Unix()
	_, err = s.db.Exec("insert into sms_verifications(phone, scene, code, ip, created_at, expires_at) values (?, ?, ?, ?, ?, ?)", phone, scene, code, ip, now, time.Now().Add(10*time.Minute).Unix())
	return err
}

func (s *Store) VerifySMS(phone, scene, code string) error {
	id, err := s.findSMS(phone, scene, code)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("update sms_verifications set consumed_at = ? where id = ? and consumed_at is null", time.Now().Unix(), id)
	return err
}

func (s *Store) CheckSMS(phone, scene, code string) error {
	_, err := s.findSMS(phone, scene, code)
	return err
}

func (s *Store) findSMS(phone, scene, code string) (int64, error) {
	var err error
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		return 0, err
	}
	if scene == "" {
		return 0, errors.New("缺少验证码用途")
	}
	row := s.db.QueryRow("select id, code, expires_at from sms_verifications where phone = ? and scene = ? and consumed_at is null order by created_at desc limit 1", phone, scene)
	var id int64
	var want string
	var expires int64
	if err := row.Scan(&id, &want, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errors.New("请先获取验证码")
		}
		return 0, err
	}
	if time.Now().Unix() > expires {
		return 0, errors.New("验证码已过期，请重新获取")
	}
	if code != want {
		return 0, errors.New("验证码错误")
	}
	return id, nil
}

func (s *Store) GetOrCreateUser(phone string) (User, bool, error) {
	var err error
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		return User{}, false, err
	}
	if u, ok, err := s.userByPhone(phone); err != nil || ok {
		if err != nil {
			return User{}, false, err
		}
		u, err = s.touchExistingUser(u)
		return u, false, err
	}
	return s.createUserWithIdentityGenerator(phone, newExternalIdentifiers)
}

const identityGenerationAttempts = 16

func newExternalIdentifiers() (string, int64) {
	return fmt.Sprintf("%d", 250000000+randInt63n(900000000)), 251000000 + randInt63n(900000)
}

func (s *Store) createUserWithIdentityGenerator(phone string, generate func() (string, int64)) (User, bool, error) {
	now := time.Now().Unix()
	var lastCollision error
	for attempt := 0; attempt < identityGenerationAttempts; attempt++ {
		openID, nid := generate()
		u := User{Phone: phone, OpenID: openID, NID: nid, Token: makeToken("pt")}
		refresh := makeToken("rt")
		u.RefreshToken = sql.NullString{String: refresh, Valid: true}
		result, err := s.db.Exec("insert into users(phone, openid, nid, token, refresh_token, created_at, last_login_at) values (?, ?, ?, ?, ?, ?, ?)", u.Phone, u.OpenID, u.NID, u.Token, refresh, now, now)
		if err == nil {
			u.ID, _ = result.LastInsertId()
			return u, true, nil
		}
		if !isUniqueConstraint(err) {
			return User{}, false, err
		}
		// A concurrent registration of the same phone is an existing-user
		// result, not an OpenID/NID collision.
		if existing, ok, lookupErr := s.userByPhone(phone); lookupErr != nil {
			return User{}, false, lookupErr
		} else if ok {
			existing, touchErr := s.touchExistingUser(existing)
			return existing, false, touchErr
		}
		lastCollision = err
	}
	return User{}, false, fmt.Errorf("生成唯一 OpenID/NID 失败，重试 %d 次: %w", identityGenerationAttempts, lastCollision)
}

func (s *Store) touchExistingUser(user User) (User, error) {
	token := makeToken("pt")
	refresh := makeToken("rt")
	_, err := s.db.Exec("update users set token = ?, refresh_token = ?, last_login_at = ? where id = ?", token, refresh, time.Now().Unix(), user.ID)
	if err != nil {
		return User{}, err
	}
	user.Token = token
	user.RefreshToken = sql.NullString{String: refresh, Valid: true}
	return user, nil
}

func isUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint failed") ||
		strings.Contains(message, "duplicate entry") ||
		strings.Contains(message, "error 1062")
}

func (s *Store) CreateUser(phone string) (User, error) {
	var err error
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		return User{}, err
	}
	u, created, err := s.GetOrCreateUser(phone)
	if err != nil {
		return User{}, err
	}
	if !created {
		return User{}, errors.New("账号已存在")
	}
	return u, nil
}

func (s *Store) UserByPhone(phone string) (User, bool, error) {
	var err error
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		return User{}, false, err
	}
	return s.userByPhone(phone)
}

func (s *Store) LatestUser() (User, error) {
	row := s.db.QueryRow("select id, phone, openid, nid, token, refresh_token, password_hash, long_token, deleted_at from users where deleted_at is null order by last_login_at desc limit 1")
	var u User
	err := row.Scan(&u.ID, &u.Phone, &u.OpenID, &u.NID, &u.Token, &u.RefreshToken, &u.PasswordHash, &u.LongToken, &u.DeletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, errors.New("未查询到账号信息")
	}
	return u, err
}

func (s *Store) RefreshToken(userID int64) (string, error) {
	token := makeToken("pt")
	refresh := makeToken("rt")
	_, err := s.db.Exec("update users set token = ?, refresh_token = ?, last_login_at = ? where id = ?", token, refresh, time.Now().Unix(), userID)
	return token, err
}

func (s *Store) RefreshByToken(refreshToken string) (User, string, error) {
	u, ok, err := s.UserByRefreshToken(refreshToken)
	if err != nil {
		return User{}, "", err
	}
	if !ok {
		return User{}, "", errors.New("刷新凭证无效")
	}
	token, err := s.RefreshToken(u.ID)
	if err != nil {
		return User{}, "", err
	}
	if fresh, ok, err := s.UserByToken(token); err == nil && ok {
		u = fresh
	} else {
		u.Token = token
	}
	return u, token, nil
}

func (s *Store) TouchLogin(userID int64) (string, error) {
	token := makeToken("pt")
	refresh := makeToken("rt")
	_, err := s.db.Exec("update users set token = ?, refresh_token = ?, last_login_at = ? where id = ?", token, refresh, time.Now().Unix(), userID)
	return token, err
}

func (s *Store) UserByToken(token string) (User, bool, error) {
	if token == "" {
		return User{}, false, errors.New("缺少登录凭证")
	}
	row := s.db.QueryRow("select id, phone, openid, nid, token, refresh_token, password_hash, long_token, deleted_at from users where token = ? and deleted_at is null", token)
	return scanUser(row)
}

func (s *Store) UserByRefreshToken(token string) (User, bool, error) {
	if token == "" {
		return User{}, false, errors.New("缺少刷新凭证")
	}
	row := s.db.QueryRow("select id, phone, openid, nid, token, refresh_token, password_hash, long_token, deleted_at from users where refresh_token = ? and deleted_at is null", token)
	return scanUser(row)
}

func (s *Store) UserByLongToken(token string) (User, bool, error) {
	if token == "" {
		return User{}, false, errors.New("缺少长连接凭证")
	}
	row := s.db.QueryRow("select id, phone, openid, nid, token, refresh_token, password_hash, long_token, deleted_at from users where long_token = ? and deleted_at is null", token)
	return scanUser(row)
}

func (s *Store) SetPasswordHash(userID int64, hash string) error {
	_, err := s.db.Exec("update users set password_hash = ? where id = ?", hash, userID)
	return err
}

func (s *Store) UpdatePhone(userID int64, phone string) error {
	var err error
	phone, err = normalizeChinaPhone(phone)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("update users set phone = ? where id = ?", phone, userID)
	return err
}

func (s *Store) DeleteUser(userID int64) error {
	now := time.Now().Unix()
	_, err := s.db.Exec("update users set phone = phone || '#deleted#' || ?, token = '', refresh_token = null, long_token = null, deleted_at = ? where id = ?", now, now, userID)
	return err
}

func (s *Store) SetLongToken(userID int64, token string) error {
	_, err := s.db.Exec("update users set long_token = ? where id = ?", token, userID)
	return err
}

func (s *Store) CreateCometSession(userID int64) (string, string, error) {
	id := randomHex(16)
	token := makeToken("ct")
	_, err := s.db.Exec("insert into comet_sessions(id, user_id, token, created_at) values (?, ?, ?, ?)", id, userID, token, time.Now().Unix())
	return id, token, err
}

func (s *Store) userByPhone(phone string) (User, bool, error) {
	row := s.db.QueryRow("select id, phone, openid, nid, token, refresh_token, password_hash, long_token, deleted_at from users where phone = ? and deleted_at is null", phone)
	return scanUser(row)
}

func scanUser(row *sql.Row) (User, bool, error) {
	var u User
	err := row.Scan(&u.ID, &u.Phone, &u.OpenID, &u.NID, &u.Token, &u.RefreshToken, &u.PasswordHash, &u.LongToken, &u.DeletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	return u, err == nil, err
}

func (s *Store) UserByOpenID(openID string) (User, bool, error) {
	openID = strings.TrimSpace(openID)
	if openID == "" {
		return User{}, false, errors.New("缺少 OpenID")
	}
	row := s.db.QueryRow("select id, phone, openid, nid, token, refresh_token, password_hash, long_token, deleted_at from users where openid = ? and deleted_at is null", openID)
	user, ok, err := scanUser(row)
	if err != nil || ok {
		return user, ok, err
	}
	// Older builds exposed users.id (and some SDK variants use NID) as the
	// external OpenID. Accept both legacy numeric aliases, then return the
	// canonical users.openid value to callers.
	legacyID, parseErr := strconv.ParseInt(openID, 10, 64)
	if parseErr != nil || legacyID <= 0 {
		return User{}, false, nil
	}
	row = s.db.QueryRow("select id, phone, openid, nid, token, refresh_token, password_hash, long_token, deleted_at from users where (id = ? or nid = ?) and deleted_at is null", legacyID, legacyID)
	return scanUser(row)
}
