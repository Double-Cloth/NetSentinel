package collection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Double-Cloth/NetSentinel/engine/rule"
)

const r001 = `{"schema_version":1,"rule_id":"R-001","name":"SSH 同账户多次认证失败","description":"同一来源在同一主机同一账户 300 秒内至少认证失败 5 次","source":"ssh","type":"count","severity":"medium","group_by":["source_host","src_ip","user.name"],"window_seconds":300,"where":{"all":[{"field":"kind","op":"eq","value":"ssh.auth_failed"}]},"threshold":5}`

var (
	ErrNotFound = errors.New("对象不存在")
	ErrConflict = errors.New("对象版本或状态冲突")
	ErrInvalid  = errors.New("输入参数无效")
)

type InputError struct {
	Path    string
	Message string
}

func (e *InputError) Error() string        { return e.Message }
func (e *InputError) Is(target error) bool { return target == ErrInvalid }

type Service struct {
	db      *sql.DB
	catalog Catalog
	reader  Reader
	dataDir string
	rule    rule.CompiledRule
	mu      sync.Mutex
	ioMu    sync.Mutex
}

func NewService(db *sql.DB, catalog Catalog, reader Reader, dataDir string) (*Service, error) {
	if reader == nil {
		reader = SFTPReader{}
	}
	draft, err := rule.Compile(rule.Snapshot{Spec: json.RawMessage(r001), SemanticsVersion: rule.SemanticsVersion})
	if err != nil {
		return nil, err
	}
	compiled, err := rule.Compile(rule.Snapshot{Spec: json.RawMessage(r001), Version: 1, SpecHash: draft.Config().SpecHash, SemanticsVersion: rule.SemanticsVersion})
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "raw"), 0700); err != nil {
		return nil, err
	}
	return &Service{db: db, catalog: catalog, reader: reader, dataDir: dataDir, rule: compiled}, nil
}

type Source struct {
	ID              string `json:"id"`
	CatalogID       string `json:"catalog_id"`
	Name            string `json:"name"`
	Format          string `json:"format"`
	Year            int    `json:"year"`
	Timezone        string `json:"timezone"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         bool   `json:"enabled"`
	RowVersion      int    `json:"row_version"`
	Generation      string `json:"generation"`
	ByteOffset      int64  `json:"byte_offset"`
	LineNo          int64  `json:"line_no"`
	LastSuccessAt   *int64 `json:"last_success_at"`
	LastError       string `json:"last_error"`
	Backlog         bool   `json:"backlog"`
	NextAt          int64  `json:"next_at"`
	Health          string `json:"health"`
	anchorHash      string
	catalogHash     string
}

func scanSource(row interface{ Scan(...any) error }) (Source, error) {
	var s Source
	var enabled int
	var backlog int
	var last sql.NullInt64
	err := row.Scan(&s.ID, &s.CatalogID, &s.catalogHash, &s.Name, &s.Format, &s.Year, &s.Timezone, &s.IntervalSeconds,
		&enabled, &s.RowVersion, &s.Generation, &s.ByteOffset, &s.LineNo, &s.anchorHash, &last, &s.LastError, &backlog, &s.NextAt)
	if err != nil {
		return s, err
	}
	s.Enabled = enabled == 1
	s.Backlog = backlog == 1
	if last.Valid {
		s.LastSuccessAt = &last.Int64
	}
	s.Health = "never_collected"
	if !s.Enabled {
		s.Health = "disabled"
	} else if s.LastError != "" {
		s.Health = "failed"
	} else if s.Backlog {
		s.Health = "backlog"
	} else if last.Valid {
		s.Health = "ready"
		if time.Now().UTC().UnixMicro() > s.NextAt+int64(s.IntervalSeconds)*1000000 {
			s.Health = "stale"
		}
	}
	return s, nil
}

const sourceColumns = `id, catalog_id, catalog_hash, name, format, year, timezone, interval_seconds, enabled, row_version, generation, byte_offset, line_no, anchor_hash, last_success_at, last_error, backlog, next_at`

func (s *Service) Sources(ctx context.Context) ([]Source, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sourceColumns+` FROM log_sources ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Source{}
	for rows.Next() {
		item, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) Source(ctx context.Context, id string) (Source, error) {
	item, err := scanSource(s.db.QueryRowContext(ctx, `SELECT `+sourceColumns+` FROM log_sources WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return item, ErrNotFound
	}
	return item, err
}

type SourceInput struct {
	CatalogID       string `json:"source_ref"`
	IntervalSeconds int    `json:"interval_seconds"`
	Year            int    `json:"year"`
	Timezone        string `json:"timezone"`
	Enabled         bool   `json:"enabled"`
	RowVersion      int    `json:"row_version"`
}

func (s *Service) CatalogItems() []map[string]string {
	result := []map[string]string{}
	for _, e := range s.catalog.entries {
		result = append(result, map[string]string{"id": e.ID, "name": e.Name, "format": e.Format})
	}
	sort.Slice(result, func(i, j int) bool { return result[i]["id"] < result[j]["id"] })
	return result
}

func (s *Service) validateInput(input SourceInput) (CatalogEntry, error) {
	entry, ok := s.catalog.Get(input.CatalogID)
	if !ok {
		return entry, &InputError{Path: "/source_ref", Message: "来源不在部署授权目录中"}
	}
	if input.IntervalSeconds < 30 || input.IntervalSeconds > 3600 {
		return entry, &InputError{Path: "/interval_seconds", Message: "采集周期须为 30—3600 秒"}
	}
	if entry.Format == "ssh-rfc3164" {
		if input.Year < 1 || input.Year > 9999 {
			return entry, &InputError{Path: "/year", Message: "请输入四位日志年份"}
		}
		if input.Timezone == "" {
			return entry, &InputError{Path: "/timezone", Message: "请输入 IANA 时区"}
		}
		if _, err := time.LoadLocation(input.Timezone); err != nil {
			return entry, &InputError{Path: "/timezone", Message: "时区无效"}
		}
	} else if input.Year != 0 || input.Timezone != "" {
		return entry, &InputError{Path: "/year", Message: "当前格式从原文读取年份与时区"}
	}
	return entry, nil
}

func (s *Service) CreateSource(ctx context.Context, input SourceInput, actor, requestID string) (Source, error) {
	entry, err := s.validateInput(input)
	if err != nil {
		return Source{}, err
	}
	id, now := randomID(), time.Now().UTC().UnixMicro()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Source{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO log_sources(id,catalog_id,catalog_hash,name,format,year,timezone,interval_seconds,enabled,next_at,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, entry.ID, entryDigest(entry), entry.Name, entry.Format, input.Year, input.Timezone, input.IntervalSeconds, boolInt(input.Enabled), now, now)
	if err != nil {
		return Source{}, ErrConflict
	}
	if err := audit(ctx, tx, actor, "source.create", "log_source", id, requestID, now); err != nil {
		return Source{}, err
	}
	if err := tx.Commit(); err != nil {
		return Source{}, err
	}
	return s.Source(ctx, id)
}

func (s *Service) UpdateSource(ctx context.Context, id string, input SourceInput, actor, requestID string) (Source, error) {
	current, err := s.Source(ctx, id)
	if err != nil {
		return Source{}, err
	}
	if current.CatalogID != input.CatalogID || input.RowVersion != current.RowVersion {
		return Source{}, ErrConflict
	}
	entry, err := s.validateInput(input)
	if err != nil {
		return Source{}, err
	}
	if current.catalogHash != entryDigest(entry) && current.ByteOffset > 0 {
		return Source{}, ErrConflict
	}
	now := time.Now().UTC().UnixMicro()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Source{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE log_sources SET catalog_hash=?,year=?,timezone=?,interval_seconds=?,enabled=?,row_version=row_version+1,next_at=? WHERE id=? AND row_version=?`,
		entryDigest(entry), input.Year, input.Timezone, input.IntervalSeconds, boolInt(input.Enabled), now, id, input.RowVersion)
	if err != nil {
		return Source{}, err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return Source{}, ErrConflict
	}
	if err := audit(ctx, tx, actor, "source.update", "log_source", id, requestID, now); err != nil {
		return Source{}, err
	}
	if err := tx.Commit(); err != nil {
		return Source{}, err
	}
	return s.Source(ctx, id)
}

func (s *Service) Retry(ctx context.Context, id, actor, requestID string) (string, error) {
	source, err := s.Source(ctx, id)
	if err != nil {
		return "", err
	}
	if !source.Enabled {
		return "", ErrConflict
	}
	idAttempt, now := randomID(), time.Now().UTC().UnixMicro()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM collection_attempts WHERE source_id=? AND status IN ('queued','running')`, id).Scan(&active); err != nil {
		return "", err
	}
	if active > 0 {
		return "", ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO collection_attempts(id,source_id,kind,status,created_at) VALUES(?,?,'retry','queued',?)`, idAttempt, id, now); err != nil {
		return "", err
	}
	if err := audit(ctx, tx, actor, "source.retry", "log_source", id, requestID, now); err != nil {
		return "", err
	}
	return idAttempt, tx.Commit()
}

func (s *Service) Recover(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE log_sources SET last_error='服务重启中断了上次采集',next_at=? WHERE EXISTS
		(SELECT 1 FROM collection_attempts WHERE source_id=log_sources.id AND status='running')`, time.Now().UTC().UnixMicro())
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE collection_attempts SET status='failed', phase='recovery', error_code='WORKER_INTERRUPTED', error_message='服务重启中断采集', finished_at=? WHERE status='running'`, time.Now().UTC().UnixMicro())
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE analysis_tasks SET status='queued', error_code='',error_message='' WHERE status='running'`)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(s.dataDir, "raw"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".log" {
			continue
		}
		relative := "raw/" + entry.Name()
		var count int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM raw_batches WHERE raw_path=?`, relative).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			if err := os.Remove(filepath.Join(s.dataDir, relative)); err != nil {
				return err
			}
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT raw_path,end_offset-start_offset,raw_hash FROM raw_batches`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var relative string
		var size int64
		var expectedHash string
		if err := rows.Scan(&relative, &size, &expectedHash); err != nil {
			return err
		}
		if filepath.Dir(relative) != "raw" {
			return errors.New("原文对象路径无效")
		}
		full := filepath.Join(s.dataDir, relative)
		info, err := os.Stat(full)
		if err != nil || !info.Mode().IsRegular() || info.Size() != size {
			return errors.New("已发布原文对象缺失或长度不符")
		}
		raw, err := os.ReadFile(full)
		if err != nil || hash(raw) != expectedHash {
			return errors.New("已发布原文对象内容校验失败")
		}
	}
	return rows.Err()
}

func (s *Service) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "采集调度失败: %v\n", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (s *Service) RunOnce(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM log_sources WHERE enabled=1 AND (next_at<=? OR EXISTS
		(SELECT 1 FROM collection_attempts WHERE source_id=log_sources.id AND status='queued')) ORDER BY next_at,id LIMIT 2`, time.Now().UTC().UnixMicro())
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = s.Collect(ctx, id)
	}
	return s.RunQueuedTasks(ctx)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func audit(ctx context.Context, tx *sql.Tx, actor, action, objectType, objectID, requestID string, now int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(id,actor_id,action,object_type,object_id,request_id,change_json,result,created_at)
		VALUES(?,?,?,?,?,?,'{}','success',?)`, randomID(), nullActor(actor), action, objectType, objectID, requestID, now)
	return err
}

func nullActor(actor string) any {
	if actor == "" {
		return nil
	}
	return actor
}
