package collection

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Double-Cloth/NetSentinel/engine/event"
	"github.com/Double-Cloth/NetSentinel/engine/finding"
)

type Batch struct {
	ID          string `json:"id"`
	SourceID    string `json:"source_id"`
	Generation  string `json:"generation"`
	StartOffset int64  `json:"start_offset"`
	EndOffset   int64  `json:"end_offset"`
	Status      string `json:"status"`
	EventCount  int    `json:"event_count"`
	CreatedAt   int64  `json:"created_at"`
}

func (s *Service) Batches(ctx context.Context) ([]Batch, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,source_id,generation,start_offset,end_offset,status,event_count,created_at FROM raw_batches ORDER BY created_at DESC,id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Batch{}
	for rows.Next() {
		var item Batch
		if err := rows.Scan(&item.ID, &item.SourceID, &item.Generation, &item.StartOffset, &item.EndOffset, &item.Status, &item.EventCount, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type Line struct {
	ID          string `json:"id"`
	LineNo      int64  `json:"line_no"`
	ByteOffset  int64  `json:"byte_offset"`
	RawHash     string `json:"raw_hash"`
	RawText     string `json:"raw_text"`
	Disposition string `json:"disposition"`
	Diagnostic  string `json:"diagnostic"`
}

func (s *Service) Lines(ctx context.Context, batchID string) ([]Line, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,line_no,byte_offset,raw_hash,raw_text,disposition,diagnostic FROM raw_lines WHERE batch_id=? ORDER BY line_no LIMIT 500`, batchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Line{}
	for rows.Next() {
		var item Line
		if err := rows.Scan(&item.ID, &item.LineNo, &item.ByteOffset, &item.RawHash, &item.RawText, &item.Disposition, &item.Diagnostic); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) Events(ctx context.Context, batchID string) ([]event.Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload_json FROM events WHERE batch_id=? ORDER BY event_time_us,id LIMIT 500`, batchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []event.Event{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var item event.Event
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type Attempt struct {
	ID            string         `json:"id"`
	SourceID      string         `json:"source_id"`
	Kind          string         `json:"kind"`
	Status        string         `json:"status"`
	Phase         string         `json:"phase"`
	ErrorCode     string         `json:"error_code"`
	ErrorMessage  string         `json:"error_message"`
	BatchID       sql.NullString `json:"-"`
	Batch         *string        `json:"batch_id"`
	ConsumedBytes int64          `json:"consumed_bytes"`
	ValidLines    int            `json:"valid_lines"`
	IgnoredLines  int            `json:"ignored_lines"`
	ErrorLines    int            `json:"error_lines"`
	CreatedAt     int64          `json:"created_at"`
	FinishedAt    *int64         `json:"finished_at"`
}

func (s *Service) Attempts(ctx context.Context, sourceID string) ([]Attempt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,source_id,kind,status,phase,error_code,error_message,batch_id,consumed_bytes,valid_lines,ignored_lines,error_lines,created_at,finished_at
		FROM collection_attempts WHERE source_id=? ORDER BY created_at DESC,id DESC LIMIT 50`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Attempt{}
	for rows.Next() {
		var item Attempt
		var finished sql.NullInt64
		if err := rows.Scan(&item.ID, &item.SourceID, &item.Kind, &item.Status, &item.Phase, &item.ErrorCode, &item.ErrorMessage, &item.BatchID,
			&item.ConsumedBytes, &item.ValidLines, &item.IgnoredLines, &item.ErrorLines, &item.CreatedAt, &finished); err != nil {
			return nil, err
		}
		if item.BatchID.Valid {
			item.Batch = &item.BatchID.String
		}
		if finished.Valid {
			item.FinishedAt = &finished.Int64
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type Task struct {
	ID              string `json:"id"`
	BatchID         string `json:"batch_id"`
	Status          string `json:"status"`
	ErrorCode       string `json:"error_code"`
	ErrorMessage    string `json:"error_message"`
	ProcessedEvents int    `json:"processed_events"`
	NewAlerts       int    `json:"new_alerts"`
	ReusedAlerts    int    `json:"reused_alerts"`
	CreatedAt       int64  `json:"created_at"`
	FinishedAt      *int64 `json:"finished_at"`
}

func (s *Service) Tasks(ctx context.Context) ([]Task, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,batch_id,status,error_code,error_message,processed_events,new_alerts,reused_alerts,created_at,finished_at
		FROM analysis_tasks ORDER BY created_at DESC,id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Task{}
	for rows.Next() {
		item, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanTask(row interface{ Scan(...any) error }) (Task, error) {
	var item Task
	var finished sql.NullInt64
	err := row.Scan(&item.ID, &item.BatchID, &item.Status, &item.ErrorCode, &item.ErrorMessage, &item.ProcessedEvents, &item.NewAlerts, &item.ReusedAlerts, &item.CreatedAt, &finished)
	if finished.Valid {
		item.FinishedAt = &finished.Int64
	}
	return item, err
}

func (s *Service) Task(ctx context.Context, id string) (Task, error) {
	item, err := scanTask(s.db.QueryRowContext(ctx, `SELECT id,batch_id,status,error_code,error_message,processed_events,new_alerts,reused_alerts,created_at,finished_at FROM analysis_tasks WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return item, ErrNotFound
	}
	return item, err
}

type Alert struct {
	ID         string          `json:"id"`
	SourceID   string          `json:"source_id"`
	BatchID    string          `json:"batch_id"`
	Status     string          `json:"status"`
	RowVersion int             `json:"row_version"`
	CreatedAt  int64           `json:"created_at"`
	Finding    finding.Finding `json:"finding"`
}

func scanAlert(row interface{ Scan(...any) error }) (Alert, error) {
	var item Alert
	var raw string
	err := row.Scan(&item.ID, &item.SourceID, &item.BatchID, &item.Status, &item.RowVersion, &item.CreatedAt, &raw)
	if err != nil {
		return item, err
	}
	err = json.Unmarshal([]byte(raw), &item.Finding)
	return item, err
}

func (s *Service) Alerts(ctx context.Context) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,source_id,batch_id,status,row_version,created_at,finding_json FROM alerts ORDER BY created_at DESC,id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Alert{}
	for rows.Next() {
		item, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) Alert(ctx context.Context, id string) (Alert, error) {
	item, err := scanAlert(s.db.QueryRowContext(ctx, `SELECT id,source_id,batch_id,status,row_version,created_at,finding_json FROM alerts WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return item, ErrNotFound
	}
	return item, err
}

type EvidenceView struct {
	Ordinal     int          `json:"ordinal"`
	EventID     string       `json:"event_id"`
	EventTimeUS int64        `json:"event_time_us"`
	RawRef      event.RawRef `json:"raw_ref"`
	RawText     string       `json:"raw_text"`
}

func (s *Service) Evidence(ctx context.Context, id string) ([]EvidenceView, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT alert_evidence.ordinal,events.id,events.event_time_us,raw_lines.batch_id,raw_lines.line_no,raw_lines.raw_hash,raw_lines.raw_text
		FROM alert_evidence JOIN events ON events.id=alert_evidence.event_id JOIN raw_lines ON raw_lines.id=events.raw_line_id
		WHERE alert_evidence.alert_id=? ORDER BY alert_evidence.ordinal LIMIT 10000`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []EvidenceView{}
	for rows.Next() {
		var item EvidenceView
		if err := rows.Scan(&item.Ordinal, &item.EventID, &item.EventTimeUS, &item.RawRef.FileID, &item.RawRef.LineNo, &item.RawRef.RawHash, &item.RawText); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) LatestAlertTime(ctx context.Context) (time.Time, error) {
	var at sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT max(created_at) FROM alerts`).Scan(&at)
	if err != nil {
		return time.Time{}, err
	}
	if !at.Valid {
		return time.Time{}, nil
	}
	return time.UnixMicro(at.Int64).UTC(), nil
}
