// Package repository 负责 SQLite 连接、迁移和持久化边界。
package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Double-Cloth/NetSentinel/backend/migrations"
	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(absolute, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	// SQLite URI 的 Windows 驱动器路径需要前置斜线。
	uriPath := filepath.ToSlash(absolute)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath}
	query := uri.Query()
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "busy_timeout(5000)")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{DB: db}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		db.Close()
		return nil, fmt.Errorf("无法启用 SQLite WAL: %v", err)
	}
	return store, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func migrationNames() ([]string, error) {
	names, err := migrations.Files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, name := range names {
		if strings.HasSuffix(name.Name(), ".sql") {
			files = append(files, name.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}

// Migrate 在一个事务内校验历史迁移摘要并应用新增迁移。
func (s *Store) Migrate(ctx context.Context) error {
	files, err := migrationNames()
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL
	)`); err != nil {
		return err
	}
	var applied int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&applied); err != nil {
		return err
	}
	if applied > len(files) {
		return fmt.Errorf("数据库迁移版本高于当前应用")
	}
	rows, err := tx.QueryContext(ctx, "SELECT name FROM schema_migrations ORDER BY name")
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(files))
	for _, name := range files {
		known[name] = true
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		if !known[name] {
			rows.Close()
			return fmt.Errorf("数据库包含当前应用未知的迁移")
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, name := range files {
		raw, err := migrations.Files.ReadFile(name)
		if err != nil {
			return err
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256(raw))
		var stored string
		err = tx.QueryRowContext(ctx, "SELECT checksum FROM schema_migrations WHERE name = ?", name).Scan(&stored)
		if err == nil {
			if stored != checksum {
				return fmt.Errorf("迁移 %s 摘要发生变化", name)
			}
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(raw)); err != nil {
			return fmt.Errorf("迁移 %s 失败: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(name, checksum, applied_at) VALUES (?, ?, ?)", name, checksum, time.Now().UTC().UnixMicro()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Ready(ctx context.Context) error {
	files, err := migrationNames()
	if err != nil {
		return err
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count); err != nil {
		return err
	}
	if count != len(files) {
		return fmt.Errorf("数据库迁移未完成")
	}
	for _, name := range files {
		raw, err := migrations.Files.ReadFile(name)
		if err != nil {
			return err
		}
		var checksum string
		if err := s.DB.QueryRowContext(ctx, "SELECT checksum FROM schema_migrations WHERE name = ?", name).Scan(&checksum); err != nil {
			return err
		}
		if checksum != fmt.Sprintf("%x", sha256.Sum256(raw)) {
			return fmt.Errorf("数据库迁移摘要不匹配")
		}
	}
	return nil
}

func WritableDirectory(directory string) error {
	file, err := os.CreateTemp(directory, ".ready-*")
	if err != nil {
		return err
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Remove(name)
}
