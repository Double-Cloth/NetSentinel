package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	SessionLifetime = 8 * time.Hour
	passwordCost    = 12
)

var (
	ErrCredentials = errors.New("用户名或密码错误")
	ErrSession     = errors.New("请先登录")
	ErrRateLimited = errors.New("登录请求过多，请稍后重试")
	usernameSyntax = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     Role   `json:"role"`
}

type Session struct {
	User        User     `json:"user"`
	Permissions []string `json:"permissions"`
	CSRFToken   string   `json:"csrf_token"`
}

type Service struct {
	db        *sql.DB
	dummyHash []byte
	slots     chan struct{}
	limits    loginLimits
}

func NewService(db *sql.DB) (*Service, error) {
	dummyHash, err := bcrypt.GenerateFromPassword([]byte(rand.Text()), passwordCost)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, dummyHash: dummyHash, slots: make(chan struct{}, 2)}, nil
}

func BootstrapAdmin(ctx context.Context, db *sql.DB, username, password string) error {
	if !usernameSyntax.MatchString(username) {
		return errors.New("用户名须为 3—32 位小写字母、数字或下划线")
	}
	if utf8.RuneCountInString(password) < 12 || len(password) > 72 || !utf8.ValidString(password) {
		return errors.New("密码至少 12 个字符且最多 72 个 UTF-8 字节")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), passwordCost)
	if err != nil {
		return err
	}
	id := rand.Text()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UnixMicro()
	result, err := tx.ExecContext(ctx, `INSERT INTO users(id, username, password_hash, role, created_at)
		SELECT ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)`, id, username, string(hash), Admin, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("数据库已有用户，无法初始化首个管理员")
	}
	if err := audit(ctx, tx, id, "auth.bootstrap", rand.Text(), now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) Login(ctx context.Context, username, password, ip, previous, requestID string) (Session, string, error) {
	if !usernameSyntax.MatchString(username) || len(password) == 0 || len(password) > 72 {
		return Session{}, "", ErrCredentials
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return Session{}, "", ErrRateLimited
	}
	if !s.limits.allow(ip, username, time.Now()) {
		return Session{}, "", ErrRateLimited
	}
	var user User
	var hash []byte
	err := s.db.QueryRowContext(ctx, `SELECT id, username, role, password_hash FROM users
		WHERE username = ? AND enabled = 1`, username).Scan(&user.ID, &user.Username, &user.Role, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		hash = s.dummyHash
	} else if err != nil {
		return Session{}, "", err
	}
	if check := bcrypt.CompareHashAndPassword(hash, []byte(password)); check != nil || err != nil {
		return Session{}, "", ErrCredentials
	}

	var random [32]byte
	rand.Read(random[:])
	token := base64.RawURLEncoding.EncodeToString(random[:])
	now := time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at <= ? OR token_hash = ?", now.UnixMicro(), digest(previous)); err != nil {
		return Session{}, "", err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, expires_at, created_at)
		SELECT ?, id, ?, ? FROM users WHERE id = ? AND enabled = 1 AND password_hash = ? AND role = ?`,
		digest(token), now.Add(SessionLifetime).UnixMicro(), now.UnixMicro(), user.ID, string(hash), user.Role)
	if err != nil {
		return Session{}, "", err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Session{}, "", err
	}
	if rows != 1 {
		return Session{}, "", ErrCredentials
	}
	if err := audit(ctx, tx, user.ID, "auth.login", requestID, now.UnixMicro()); err != nil {
		return Session{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return Session{}, "", err
	}
	return sessionFor(user, token), token, nil
}

func (s *Service) Current(ctx context.Context, token string) (Session, error) {
	if len(token) != base64.RawURLEncoding.EncodedLen(32) {
		return Session{}, ErrSession
	}
	var user User
	err := s.db.QueryRowContext(ctx, `SELECT users.id, users.username, users.role FROM sessions
		JOIN users ON users.id = sessions.user_id
		WHERE token_hash = ? AND expires_at > ? AND users.enabled = 1`, digest(token), time.Now().UnixMicro()).
		Scan(&user.ID, &user.Username, &user.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSession
	}
	if err != nil {
		return Session{}, err
	}
	return sessionFor(user, token), nil
}

func (s *Service) Logout(ctx context.Context, user User, token, requestID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash = ? AND user_id = ?", digest(token), user.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrSession
	}
	if err := audit(ctx, tx, user.ID, "auth.logout", requestID, time.Now().UnixMicro()); err != nil {
		return err
	}
	return tx.Commit()
}

func sessionFor(user User, token string) Session {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("csrf-v1"))
	return Session{User: user, Permissions: []string{"auth.me", "auth.logout"}, CSRFToken: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
}

func digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func audit(ctx context.Context, tx *sql.Tx, actorID, action, requestID string, now int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(id, actor_id, action, object_type, object_id, request_id, change_json, result, created_at)
		VALUES (?, ?, ?, 'user', ?, ?, '{}', 'success', ?)`, rand.Text(), actorID, action, actorID, requestID, now)
	return err
}
