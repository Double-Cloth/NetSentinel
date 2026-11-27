package collection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Double-Cloth/NetSentinel/engine/event"
	"github.com/Double-Cloth/NetSentinel/engine/finding"
	"github.com/Double-Cloth/NetSentinel/engine/rule"
	"github.com/Double-Cloth/NetSentinel/engine/runtime"
)

type iterator struct {
	items []event.Event
	index int
}

func (i *iterator) Next(context.Context) (event.Event, bool, error) {
	if i.index >= len(i.items) {
		return event.Event{}, false, nil
	}
	item := i.items[i.index]
	i.index++
	return item, true, nil
}

type sink struct{ items []finding.Finding }

func (s *sink) Write(_ context.Context, item finding.Finding) error {
	s.items = append(s.items, item)
	return nil
}

// RunQueuedTasks 从固定来源前缀重放，以新批次的触发事件确定发布所有权。
func (s *Service) RunQueuedTasks(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id,batch_id FROM analysis_tasks WHERE status='queued' ORDER BY created_at,id LIMIT 2`)
	if err != nil {
		return err
	}
	type task struct{ id, batch string }
	queue := []task{}
	for rows.Next() {
		var t task
		if err := rows.Scan(&t.id, &t.batch); err != nil {
			rows.Close()
			return err
		}
		queue = append(queue, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, t := range queue {
		if err := s.runTask(ctx, t.id, t.batch); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) runTask(ctx context.Context, taskID, batchID string) (returnErr error) {
	now := time.Now().UTC().UnixMicro()
	result, err := s.db.ExecContext(ctx, `UPDATE analysis_tasks SET status='running' WHERE id=? AND status='queued'`, taskID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrConflict
	}
	defer func() {
		if returnErr != nil {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.failTask(recoveryCtx, taskID, "ANALYSIS_FAILED")
		}
	}()
	var sourceID string
	var endOffset int64
	err = s.db.QueryRowContext(ctx, `SELECT source_id,end_offset FROM raw_batches WHERE id=?`, batchID).Scan(&sourceID, &endOffset)
	if err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT events.batch_id,events.payload_json FROM events JOIN raw_lines ON raw_lines.id=events.raw_line_id
		WHERE events.source_id=? AND raw_lines.byte_offset<? ORDER BY events.event_time_us,raw_lines.byte_offset,events.id`, sourceID, endOffset)
	if err != nil {
		return err
	}
	items := []event.Event{}
	owned := map[string]bool{}
	for rows.Next() {
		var batch, raw string
		if err := rows.Scan(&batch, &raw); err != nil {
			rows.Close()
			return err
		}
		var item event.Event
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			rows.Close()
			return err
		}
		item.DatasetID = "source-scope-v2:" + sourceID
		item.Index = int64(len(items) + 1)
		items = append(items, item)
		if batch == batchID {
			owned[item.ID] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	out := &sink{}
	_, err = runtime.Run(ctx, &iterator{items: items}, []rule.CompiledRule{s.rule}, runtime.DefaultOptions(), out)
	if err != nil {
		s.failTask(ctx, taskID, "ENGINE_FAILED")
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	newAlerts, reused := 0, 0
	for _, item := range out.items {
		if !owned[item.TriggerEventID] {
			continue
		}
		var existingID, digest string
		err = tx.QueryRowContext(ctx, `SELECT id,result_digest FROM alerts WHERE fingerprint=?`, item.Fingerprint).Scan(&existingID, &digest)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == nil {
			if digest != item.ResultDigest {
				return errors.New("已有告警证据摘要冲突")
			}
			reused++
		} else {
			existingID = randomID()
			payload, _ := json.Marshal(item)
			_, err = tx.ExecContext(ctx, `INSERT INTO alerts(id,source_id,batch_id,trigger_event_id,fingerprint,result_digest,finding_json,created_at)
				VALUES(?,?,?,?,?,?,?,?)`, existingID, sourceID, batchID, item.TriggerEventID, item.Fingerprint, item.ResultDigest, string(payload), now)
			if err != nil {
				return err
			}
			for ordinal, evidence := range item.Evidence {
				_, err = tx.ExecContext(ctx, `INSERT INTO alert_evidence(alert_id,ordinal,event_id) VALUES(?,?,?)`, existingID, ordinal+1, evidence.EventID)
				if err != nil {
					return err
				}
			}
			newAlerts++
		}
		_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO task_alerts(task_id,alert_id) VALUES(?,?)`, taskID, existingID)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE analysis_tasks SET status='succeeded',processed_events=?,new_alerts=?,reused_alerts=?,finished_at=? WHERE id=? AND status='running'`, len(items), newAlerts, reused, now, taskID)
	if err != nil {
		return err
	}
	if err := audit(ctx, tx, "", "task.publish", "analysis_task", taskID, taskID, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		s.failTask(ctx, taskID, "COMMIT_FAILED")
		return err
	}
	return nil
}

func (s *Service) failTask(ctx context.Context, id, code string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE analysis_tasks SET status='failed',error_code=?,error_message='分析失败，请检查来源及规则后重试',finished_at=? WHERE id=? AND status='running'`, code, time.Now().UTC().UnixMicro(), id)
}

func (s *Service) RetryTask(ctx context.Context, id, actor, requestID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE analysis_tasks SET status='queued',error_code='',error_message='',finished_at=NULL WHERE id=? AND status='failed'`, id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrConflict
	}
	if err := audit(ctx, tx, actor, "task.retry", "analysis_task", id, requestID, time.Now().UTC().UnixMicro()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) RuleInfo() map[string]any {
	return map[string]any{"rule_id": "R-001", "version": 1, "spec_hash": s.rule.Config().SpecHash, "spec": json.RawMessage(s.rule.JSON()), "engine_semantics_version": rule.SemanticsVersion}
}
