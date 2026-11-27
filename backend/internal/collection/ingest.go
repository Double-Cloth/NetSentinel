package collection

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Double-Cloth/NetSentinel/engine/event"
)

func randomID() string { return rand.Text() }

type parsedLine struct {
	id          string
	offset      int64
	lineNo      int64
	rawHash     string
	text        string
	disposition string
	diagnostic  string
	event       event.Event
}

// Collect 只消费完整行；正式批次、断点与任务意图在同一事务提交。
func (s *Service) Collect(ctx context.Context, sourceID string) (returnErr error) {
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	source, err := s.Source(ctx, sourceID)
	if err != nil {
		return err
	}
	if !source.Enabled {
		return ErrConflict
	}
	now := time.Now().UTC().UnixMicro()
	var attemptID, kind string
	err = s.db.QueryRowContext(ctx, `SELECT id,kind FROM collection_attempts WHERE source_id=? AND status='queued' ORDER BY created_at LIMIT 1`, sourceID).Scan(&attemptID, &kind)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == sql.ErrNoRows {
		attemptID, kind = randomID(), "scheduled"
		_, err = s.db.ExecContext(ctx, `INSERT INTO collection_attempts(id,source_id,kind,status,phase,created_at) VALUES(?,?,?,'running','pull',?)`, attemptID, sourceID, kind, now)
	} else {
		_, err = s.db.ExecContext(ctx, `UPDATE collection_attempts SET status='running',phase='pull' WHERE id=? AND status='queued'`, attemptID)
	}
	if err != nil {
		return err
	}
	defer func() {
		if returnErr != nil {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.failAttempt(recoveryCtx, attemptID, sourceID, "COLLECTION_FAILED", "采集事务失败，请查看服务日志并重试")
		}
	}()
	entry, ok := s.catalog.Get(source.CatalogID)
	if !ok {
		s.failAttempt(ctx, attemptID, sourceID, "SOURCE_CATALOG_MISSING", "授权源目录条目不可用，请检查部署配置")
		return ErrInvalid
	}
	if source.catalogHash != entryDigest(entry) {
		s.failAttempt(ctx, attemptID, sourceID, "SOURCE_CATALOG_CHANGED", "授权源目录条目已变化，请由管理员确认来源配置")
		return ErrConflict
	}
	cursor := Cursor{Generation: source.Generation, Offset: source.ByteOffset, LineNo: source.LineNo, AnchorHash: source.anchorHash}
	pullCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	chunk, err := s.reader.Read(pullCtx, entry, cursor)
	cancel()
	if err != nil {
		s.failAttempt(ctx, attemptID, sourceID, "SOURCE_READ_FAILED", err.Error())
		return err
	}
	if chunk.Generation == "" || (cursor.Generation != "" && cursor.Generation != chunk.Generation) || len(chunk.Bytes) > maxRead ||
		(len(chunk.Bytes) > 0 && chunk.Bytes[len(chunk.Bytes)-1] != '\n') {
		err = errors.New("采集结果不符合代次或完整行契约")
		s.failAttempt(ctx, attemptID, sourceID, "SOURCE_CONTRACT_INVALID", err.Error())
		return err
	}
	if len(chunk.Bytes) == 0 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		result, err := tx.ExecContext(ctx, `UPDATE log_sources SET generation=?,last_success_at=?,last_error='',backlog=?,next_at=?
			WHERE id=? AND row_version=? AND byte_offset=? AND generation=?`, chunk.Generation, now, boolInt(chunk.Backlog), now+int64(source.IntervalSeconds)*1000000,
			sourceID, source.RowVersion, source.ByteOffset, source.Generation)
		if err != nil {
			s.failAttempt(ctx, attemptID, sourceID, "CURSOR_CONFLICT", "来源配置或断点变化")
			return err
		}
		count, _ := result.RowsAffected()
		if count != 1 {
			return ErrConflict
		}
		if _, err = tx.ExecContext(ctx, `UPDATE collection_attempts SET status='succeeded',phase='',finished_at=? WHERE id=?`, now, attemptID); err != nil {
			return err
		}
		return tx.Commit()
	}
	batchID := hash([]byte(fmt.Sprintf("batch-v1:%s:%s:%d:%d", sourceID, chunk.Generation, source.ByteOffset, source.ByteOffset+int64(len(chunk.Bytes)))))
	lines := []parsedLine{}
	offset, lineNo := source.ByteOffset, source.LineNo
	valid, ignored, invalid := 0, 0, 0
	for _, raw := range bytes.SplitAfter(chunk.Bytes, []byte{'\n'}) {
		if len(raw) == 0 {
			continue
		}
		if len(raw) > maxLine {
			err = errors.New("日志行超过 64 KiB")
			s.failAttempt(ctx, attemptID, sourceID, "LINE_TOO_LONG", err.Error())
			return err
		}
		lineNo++
		content := bytes.TrimSuffix(raw, []byte{'\n'})
		text := strings.ToValidUTF8(string(content), "�")
		item := parsedLine{id: hash([]byte(fmt.Sprintf("line-v1:%s:%s:%d", sourceID, chunk.Generation, offset))), offset: offset, lineNo: lineNo, rawHash: hash(raw), text: text}
		if !utf8.Valid(content) {
			item.disposition, item.diagnostic = "error", "UTF8_INVALID"
		} else {
			item.event, item.disposition, item.diagnostic = ParseLine(ParseConfig{Format: source.Format, Year: source.Year, Timezone: source.Timezone, SourceHost: entry.SourceHost}, text)
		}
		switch item.disposition {
		case "event":
			valid++
		case "ignored":
			ignored++
		default:
			invalid++
		}
		if item.disposition == "event" {
			item.event.ID = hash([]byte(fmt.Sprintf("collected-event-v1:%s:%s:%d", sourceID, chunk.Generation, offset)))
			item.event.DatasetID = batchID
			item.event.RawRef = event.RawRef{FileID: batchID, LineNo: lineNo, RawHash: item.rawHash}
		}
		lines = append(lines, item)
		offset += int64(len(raw))
	}
	// 批内排序由事件时间及原始行序决定；保存的索引从 1 递增。
	indices := make([]int, 0, valid)
	for i := range lines {
		if lines[i].disposition == "event" {
			indices = append(indices, i)
		}
	}
	sort.SliceStable(indices, func(i, j int) bool {
		a, b := lines[indices[i]], lines[indices[j]]
		if a.event.TimeUS == b.event.TimeUS {
			return a.lineNo < b.lineNo
		}
		return a.event.TimeUS < b.event.TimeUS
	})
	var latest sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT max(event_time_us) FROM events WHERE source_id=?`, sourceID).Scan(&latest); err != nil {
		return err
	}
	for n, i := range indices {
		lines[i].event.Index = int64(n + 1)
		if err := lines[i].event.Validate(); err != nil {
			s.failAttempt(ctx, attemptID, sourceID, "EVENT_INVALID", "解析事件不符合引擎契约")
			return err
		}
		if latest.Valid && lines[i].event.TimeUS < latest.Int64 {
			err = errors.New("新增事件时间早于已发布事件，需独立回填")
			s.failAttempt(ctx, attemptID, sourceID, "LATE_EVENT", err.Error())
			return err
		}
	}
	relative := "raw/" + batchID + ".log"
	full := filepath.Join(s.dataDir, relative)
	created, err := writeRaw(full, chunk.Bytes)
	if err != nil {
		s.failAttempt(ctx, attemptID, sourceID, "RAW_WRITE_FAILED", "原文写入失败")
		return err
	}
	committed := false
	defer func() {
		if !committed && created {
			_ = os.Remove(full)
		}
	}()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	nextAt := now + int64(source.IntervalSeconds)*1000000
	if chunk.Backlog {
		nextAt = now
	}
	result, err := tx.ExecContext(ctx, `UPDATE log_sources SET generation=?,byte_offset=?,line_no=?,anchor_hash=?,last_success_at=?,last_error='',backlog=?,next_at=?
		WHERE id=? AND row_version=? AND generation=? AND byte_offset=?`, chunk.Generation, offset, lineNo, chunk.AnchorHash, now, boolInt(chunk.Backlog),
		nextAt, sourceID, source.RowVersion, source.Generation, source.ByteOffset)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrConflict
	}
	status := "diagnostic"
	if valid > 0 {
		status = "ready"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO raw_batches(id,source_id,generation,start_offset,end_offset,raw_path,raw_hash,status,event_count,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, batchID, sourceID, chunk.Generation, source.ByteOffset, offset, relative, hash(chunk.Bytes), status, valid, now)
	if err != nil {
		return err
	}
	for _, item := range lines {
		_, err = tx.ExecContext(ctx, `INSERT INTO raw_lines(id,batch_id,source_id,generation,byte_offset,line_no,raw_hash,raw_text,disposition,diagnostic)
			VALUES(?,?,?,?,?,?,?,?,?,?)`, item.id, batchID, sourceID, chunk.Generation, item.offset, item.lineNo, item.rawHash, item.text, item.disposition, item.diagnostic)
		if err != nil {
			return err
		}
		if item.disposition == "event" {
			payload, _ := json.Marshal(item.event)
			_, err = tx.ExecContext(ctx, `INSERT INTO events(id,batch_id,source_id,event_time_us,raw_line_id,payload_json) VALUES(?,?,?,?,?,?)`,
				item.event.ID, batchID, sourceID, item.event.TimeUS, item.id, string(payload))
			if err != nil {
				return err
			}
		}
	}
	if valid > 0 && source.Format != "nginx-combined" {
		_, err = tx.ExecContext(ctx, `INSERT INTO analysis_tasks(id,batch_id,status,created_at) VALUES(?,?,'queued',?)`, randomID(), batchID, now)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE collection_attempts SET status='succeeded',phase='',batch_id=?,consumed_bytes=?,valid_lines=?,ignored_lines=?,error_lines=?,finished_at=? WHERE id=?`,
		batchID, len(chunk.Bytes), valid, ignored, invalid, now, attemptID)
	if err != nil {
		return err
	}
	if err := audit(ctx, tx, "", "source.collect", "log_source", sourceID, attemptID, now); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func writeRaw(full string, raw []byte) (bool, error) {
	if existing, err := os.ReadFile(full); err == nil {
		if bytes.Equal(existing, raw) {
			return false, nil
		}
		return false, errors.New("已有原文对象摘要冲突")
	}
	file, err := os.CreateTemp(filepath.Dir(full), ".batch-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return false, err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return false, err
	}
	if err = file.Close(); err != nil {
		return false, err
	}
	if err = os.Rename(file.Name(), full); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) failAttempt(ctx context.Context, attemptID, sourceID, code, message string) {
	now := time.Now().UTC().UnixMicro()
	// 对外错误不包含连接地址、路径或凭据。
	result, _ := s.db.ExecContext(ctx, `UPDATE collection_attempts SET status='failed',phase='pull',error_code=?,error_message=?,finished_at=? WHERE id=? AND status='running'`, code, message, now, attemptID)
	if result != nil {
		count, _ := result.RowsAffected()
		if count == 1 {
			_, _ = s.db.ExecContext(ctx, `UPDATE log_sources SET last_error=?,backlog=0,next_at=? WHERE id=?`, message, now+60*1000000, sourceID)
		}
	}
}
