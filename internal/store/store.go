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

type DueCancellation struct {
	UserID int64
	OpenID string
}

const firstUserID int64 = 100000001

const (
	accessTokenTTL  = 2 * time.Hour
	refreshTokenTTL = 30 * 24 * time.Hour
)

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
	token varchar(128) not null,
	refresh_token varchar(128),
	token_expires_at bigint not null,
	refresh_token_expires_at bigint not null,
	token_revoked_at bigint,
	long_token text,
	password_hash text,
	cancellation_status int not null default 1,
	cancellation_at bigint,
	deleted_at bigint,
	created_at bigint not null,
	last_login_at bigint not null
) auto_increment=100000001;
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
create table if not exists auth_sessions (
	id varchar(64) primary key,
	user_id bigint not null,
	access_token varchar(128) unique not null,
	refresh_token varchar(128) unique not null,
	access_expires_at bigint not null,
	refresh_expires_at bigint not null,
	revoked_at bigint,
	created_at bigint not null,
	refreshed_at bigint not null,
	index idx_auth_sessions_user(user_id)
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
		if err := s.migrateUnifiedUserIDs(); err != nil {
			return err
		}
		return s.migrateLegacyAuthSessions()
	}
	_, err := s.db.Exec(`
create table if not exists users (
	id integer primary key autoincrement,
	phone varchar(64) unique not null,
	token varchar(128) not null,
	refresh_token varchar(128),
	token_expires_at bigint not null,
	refresh_token_expires_at bigint not null,
	token_revoked_at bigint,
	long_token text,
	password_hash text,
	cancellation_status int not null default 1,
	cancellation_at bigint,
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
create table if not exists auth_sessions (
	id varchar(64) primary key,
	user_id bigint not null,
	access_token varchar(128) unique not null,
	refresh_token varchar(128) unique not null,
	access_expires_at bigint not null,
	refresh_expires_at bigint not null,
	revoked_at bigint,
	created_at bigint not null,
	refreshed_at bigint not null
);
create index if not exists idx_auth_sessions_user on auth_sessions(user_id);
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
	if err := s.migrateUnifiedUserIDs(); err != nil {
		return err
	}
	return s.migrateLegacyAuthSessions()
}

func (s *Store) LogRequest(method, host, path string, bodyBytes int64) {
	_, _ = s.db.Exec("insert into request_log(created_at, method, host, path, body_bytes) values (?, ?, ?, ?, ?)", time.Now().Unix(), method, host, path, bodyBytes)
}

func (s *Store) ensureColumns() error {
	for name, definition := range map[string]string{
		"password_hash":            "text",
		"refresh_token":            "varchar(128)",
		"token_expires_at":         "bigint not null default 0",
		"refresh_token_expires_at": "bigint not null default 0",
		"token_revoked_at":         "bigint",
		"cancellation_status":      "int not null default 1",
		"cancellation_at":          "bigint",
		"deleted_at":               "bigint",
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

type storedUser struct {
	oldID, newID                          int64
	phone, token                          string
	refreshToken, longToken, passwordHash sql.NullString
	tokenExpiresAt, refreshTokenExpiresAt int64
	tokenRevokedAt                        sql.NullInt64
	cancellationStatus                    int
	cancellationAt, deletedAt             sql.NullInt64
	createdAt, lastLoginAt                int64
}

func (s *Store) migrateUnifiedUserIDs() error {
	hasOpenID, err := s.hasUserColumn("openid")
	if err != nil {
		return err
	}
	hasNID, err := s.hasUserColumn("nid")
	if err != nil {
		return err
	}
	rows, err := s.db.Query(`select id, phone, token, refresh_token, token_expires_at, refresh_token_expires_at,
		token_revoked_at, long_token, password_hash,
		cancellation_status, cancellation_at, deleted_at, created_at, last_login_at from users order by id`)
	if err != nil {
		return err
	}
	users := []storedUser{}
	for rows.Next() {
		var user storedUser
		if err := rows.Scan(&user.oldID, &user.phone, &user.token, &user.refreshToken, &user.tokenExpiresAt,
			&user.refreshTokenExpiresAt, &user.tokenRevokedAt, &user.longToken,
			&user.passwordHash, &user.cancellationStatus, &user.cancellationAt, &user.deletedAt,
			&user.createdAt, &user.lastLoginAt); err != nil {
			rows.Close()
			return err
		}
		user.newID = firstUserID + int64(len(users))
		users = append(users, user)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	needsRenumber := len(users) > 0 && users[0].oldID != firstUserID
	for index := range users {
		if users[index].oldID != users[index].newID {
			needsRenumber = true
			break
		}
	}
	if !hasOpenID && !hasNID && !needsRenumber {
		if err := s.setUserSequence(users); err != nil {
			return err
		}
		return s.deleteOrphanCometSessions()
	}
	if s.driver == "mysql" {
		err = s.migrateMySQLUsers(users, hasOpenID, hasNID)
	} else {
		err = s.rebuildSQLiteUsers(users)
	}
	if err != nil {
		return err
	}
	return s.deleteOrphanCometSessions()
}

func (s *Store) deleteOrphanCometSessions() error {
	if _, err := s.db.Exec("delete from comet_sessions where not exists (select 1 from users where users.id = comet_sessions.user_id)"); err != nil {
		return err
	}
	_, err := s.db.Exec("delete from auth_sessions where not exists (select 1 from users where users.id = auth_sessions.user_id)")
	return err
}

func (s *Store) hasUserColumn(name string) (bool, error) {
	if s.driver == "mysql" {
		var count int
		err := s.db.QueryRow(`select count(*) from information_schema.columns
			where table_schema = database() and table_name = 'users' and column_name = ?`, name).Scan(&count)
		return count > 0, err
	}
	rows, err := s.db.Query("pragma table_info(users)")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var column, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &column, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if column == name {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) rebuildSQLiteUsers(users []storedUser) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("drop table if exists users_unified"); err != nil {
		return err
	}
	if _, err := tx.Exec(`create table users_unified (
		id integer primary key autoincrement,
		phone varchar(64) unique not null,
		token varchar(128) not null,
		refresh_token varchar(128), token_expires_at bigint not null, refresh_token_expires_at bigint not null,
		token_revoked_at bigint, long_token text, password_hash text,
		cancellation_status int not null default 1, cancellation_at bigint, deleted_at bigint,
		created_at bigint not null, last_login_at bigint not null
	)`); err != nil {
		return err
	}
	for _, user := range users {
		if _, err := tx.Exec(`insert into users_unified(id, phone, token, refresh_token, token_expires_at,
			refresh_token_expires_at, token_revoked_at, long_token, password_hash,
			cancellation_status, cancellation_at, deleted_at, created_at, last_login_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			user.newID, user.phone, user.token, user.refreshToken, user.tokenExpiresAt,
			user.refreshTokenExpiresAt, user.tokenRevokedAt, user.longToken, user.passwordHash,
			user.cancellationStatus, user.cancellationAt, user.deletedAt, user.createdAt, user.lastLoginAt); err != nil {
			return err
		}
		if user.oldID != user.newID {
			if _, err := tx.Exec("update comet_sessions set user_id = ? where user_id = ?", user.newID, user.oldID); err != nil {
				return err
			}
			if _, err := tx.Exec("update auth_sessions set user_id = ? where user_id = ?", user.newID, user.oldID); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec("drop table users"); err != nil {
		return err
	}
	if _, err := tx.Exec("alter table users_unified rename to users"); err != nil {
		return err
	}
	if _, err := tx.Exec("delete from sqlite_sequence where name = 'users'"); err != nil {
		return err
	}
	sequence := firstUserID - 1
	if len(users) > 0 {
		sequence = users[len(users)-1].newID
	}
	if _, err := tx.Exec("insert into sqlite_sequence(name, seq) values ('users', ?)", sequence); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) migrateMySQLUsers(users []storedUser, hasOpenID, hasNID bool) error {
	const temporaryBase int64 = 4000000000000000000
	for index, user := range users {
		if user.oldID == user.newID {
			continue
		}
		temporaryID := temporaryBase + int64(index)
		if _, err := s.db.Exec("update comet_sessions set user_id = ? where user_id = ?", temporaryID, user.oldID); err != nil {
			return err
		}
		if _, err := s.db.Exec("update auth_sessions set user_id = ? where user_id = ?", temporaryID, user.oldID); err != nil {
			return err
		}
		if _, err := s.db.Exec("update users set id = ? where id = ?", temporaryID, user.oldID); err != nil {
			return err
		}
	}
	for index, user := range users {
		if user.oldID == user.newID {
			continue
		}
		temporaryID := temporaryBase + int64(index)
		if _, err := s.db.Exec("update users set id = ? where id = ?", user.newID, temporaryID); err != nil {
			return err
		}
		if _, err := s.db.Exec("update comet_sessions set user_id = ? where user_id = ?", user.newID, temporaryID); err != nil {
			return err
		}
		if _, err := s.db.Exec("update auth_sessions set user_id = ? where user_id = ?", user.newID, temporaryID); err != nil {
			return err
		}
	}
	if hasOpenID {
		if _, err := s.db.Exec("alter table users drop column openid"); err != nil {
			return err
		}
	}
	if hasNID {
		if _, err := s.db.Exec("alter table users drop column nid"); err != nil {
			return err
		}
	}
	return s.setUserSequence(users)
}

func (s *Store) setUserSequence(users []storedUser) error {
	sequence := firstUserID - 1
	if len(users) > 0 {
		sequence = users[len(users)-1].newID
	}
	if s.driver == "mysql" {
		_, err := s.db.Exec("alter table users auto_increment = " + strconv.FormatInt(sequence+1, 10))
		return err
	}
	result, err := s.db.Exec("update sqlite_sequence set seq = ? where name = 'users'", sequence)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil || updated > 0 {
		return err
	}
	_, err = s.db.Exec("insert into sqlite_sequence(name, seq) values ('users', ?)", sequence)
	return err
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
	return s.createUser(phone)
}

func (s *Store) createUser(phone string) (User, bool, error) {
	now := time.Now().Unix()
	result, err := s.db.Exec(`insert into users(phone, token, refresh_token, token_expires_at,
		refresh_token_expires_at, token_revoked_at, created_at, last_login_at) values (?, ?, ?, ?, ?, null, ?, ?)`,
		phone, "", nil, 0, 0, now, now)
	if err == nil {
		userID, err := result.LastInsertId()
		if err != nil {
			return User{}, false, err
		}
		u, err := s.issueAuthSession(userID)
		return u, true, err
	}
	if !isUniqueConstraint(err) {
		return User{}, false, err
	}
	existing, ok, lookupErr := s.userByPhone(phone)
	if lookupErr != nil || !ok {
		return User{}, false, lookupErr
	}
	existing, touchErr := s.touchExistingUser(existing)
	return existing, false, touchErr
}

func (s *Store) touchExistingUser(user User) (User, error) {
	return s.issueAuthSession(user.ID)
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
	u, ok, err := scanUser(s.db.QueryRow("select id, phone, token, refresh_token, password_hash, long_token, deleted_at from users where deleted_at is null order by last_login_at desc limit 1"))
	if !ok && err == nil {
		return User{}, errors.New("未查询到账号信息")
	}
	return u, err
}

func (s *Store) RefreshToken(userID int64) (string, error) {
	u, err := s.issueAuthSession(userID)
	return u.Token, err
}

func (s *Store) RefreshByToken(refreshToken string) (User, string, error) {
	return s.refreshAuthSession(refreshToken)
}

func (s *Store) TouchLogin(userID int64) (string, error) {
	u, err := s.issueAuthSession(userID)
	return u.Token, err
}

func newTokenPair(now int64) (string, string, int64, int64) {
	return makeToken("pt"), makeToken("rt"), now + int64(accessTokenTTL/time.Second), now + int64(refreshTokenTTL/time.Second)
}

func (s *Store) UserByToken(token string) (User, bool, error) {
	if token == "" {
		return User{}, false, errors.New("缺少登录凭证")
	}
	row := s.db.QueryRow(`select u.id, u.phone, s.access_token, s.refresh_token, u.password_hash, u.long_token, u.deleted_at
		from auth_sessions s join users u on u.id = s.user_id
		where s.access_token = ? and s.revoked_at is null and s.access_expires_at >= ?
		and u.deleted_at is null and u.token_revoked_at is null`, token, time.Now().Unix())
	return scanUser(row)
}

func (s *Store) UserByRefreshToken(token string) (User, bool, error) {
	if token == "" {
		return User{}, false, errors.New("缺少刷新凭证")
	}
	row := s.db.QueryRow(`select u.id, u.phone, s.access_token, s.refresh_token, u.password_hash, u.long_token, u.deleted_at
		from auth_sessions s join users u on u.id = s.user_id
		where s.refresh_token = ? and s.revoked_at is null and s.refresh_expires_at >= ?
		and u.deleted_at is null and u.token_revoked_at is null`, token, time.Now().Unix())
	return scanUser(row)
}

func (s *Store) UserByLongToken(token string) (User, bool, error) {
	if token == "" {
		return User{}, false, errors.New("缺少长连接凭证")
	}
	row := s.db.QueryRow("select id, phone, token, refresh_token, password_hash, long_token, deleted_at from users where long_token = ? and deleted_at is null and token_revoked_at is null", token)
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
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`update users set phone = phone || '#deleted#' || ?, token = '', refresh_token = null,
		token_revoked_at = ?, long_token = null, deleted_at = ? where id = ?`, now, now, now, userID); err != nil {
		return err
	}
	if _, err := tx.Exec("update auth_sessions set revoked_at = ? where user_id = ? and revoked_at is null", now, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeTokens(userID int64) error {
	now := time.Now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("update users set token_revoked_at = ? where id = ? and deleted_at is null", now, userID); err != nil {
		return err
	}
	if _, err := tx.Exec("update auth_sessions set revoked_at = ? where user_id = ? and revoked_at is null", now, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Cancellation(userID int64) (int, int64, error) {
	var status int
	var cancelAt sql.NullInt64
	err := s.db.QueryRow("select cancellation_status, cancellation_at from users where id = ? and deleted_at is null", userID).Scan(&status, &cancelAt)
	if err != nil {
		return 0, 0, err
	}
	return status, cancelAt.Int64, nil
}

func (s *Store) SetCancellation(userID int64, status int, cancelAt int64) error {
	var at any
	if cancelAt > 0 {
		at = cancelAt
	}
	_, err := s.db.Exec("update users set cancellation_status = ?, cancellation_at = ? where id = ? and deleted_at is null", status, at, userID)
	return err
}

func (s *Store) DueCancellations(now int64, limit int) ([]DueCancellation, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`select id from users
		where cancellation_status = 2 and cancellation_at is not null and cancellation_at <= ? and deleted_at is null
		order by cancellation_at, id limit ?`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]DueCancellation, 0)
	for rows.Next() {
		var item DueCancellation
		if err := rows.Scan(&item.UserID); err != nil {
			return nil, err
		}
		item.OpenID = strconv.FormatInt(item.UserID, 10)
		items = append(items, item)
	}
	return items, rows.Err()
}

// CompleteCancellation soft-deletes only an account whose cooling-off period
// is still due. The conditional update prevents a concurrent cancellation from
// deleting an account after the user has withdrawn the application.
func (s *Store) CompleteCancellation(userID, now int64) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`update users set phone = phone || '#deleted#' || ?, token = '', refresh_token = null,
		token_revoked_at = ?, long_token = null, deleted_at = ?
		where id = ? and cancellation_status = 2 and cancellation_at is not null and cancellation_at <= ? and deleted_at is null`,
		now, now, now, userID, now)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if changed > 0 {
		if _, err := tx.Exec("update auth_sessions set revoked_at = ? where user_id = ? and revoked_at is null", now, userID); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return changed > 0, nil
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
	row := s.db.QueryRow("select id, phone, token, refresh_token, password_hash, long_token, deleted_at from users where phone = ? and deleted_at is null", phone)
	return scanUser(row)
}

func scanUser(row *sql.Row) (User, bool, error) {
	var u User
	err := row.Scan(&u.ID, &u.Phone, &u.Token, &u.RefreshToken, &u.PasswordHash, &u.LongToken, &u.DeletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err == nil {
		setUserAliases(&u)
	}
	return u, err == nil, err
}

func setUserAliases(user *User) {
	user.OpenID = strconv.FormatInt(user.ID, 10)
	user.NID = user.ID
}

func (s *Store) UserByOpenID(openID string) (User, bool, error) {
	openID = strings.TrimSpace(openID)
	if openID == "" {
		return User{}, false, errors.New("缺少 OpenID")
	}
	userID, parseErr := strconv.ParseInt(openID, 10, 64)
	if parseErr != nil || userID <= 0 {
		return User{}, false, nil
	}
	return scanUser(s.db.QueryRow("select id, phone, token, refresh_token, password_hash, long_token, deleted_at from users where id = ? and deleted_at is null", userID))
}
