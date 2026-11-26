package repository

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"modernc.org/sqlite"
)

func TestWALWriterRollbackAndCommitVisibility(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "visibility.db")
	writer, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	observer, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	// 立即报告竞争，使实验不依赖锁等待时长。
	if _, err := observer.DB.ExecContext(ctx, "PRAGMA busy_timeout=0"); err != nil {
		t.Fatal(err)
	}
	const insert = `INSERT INTO audit_logs(id,action,object_type,object_id,request_id,change_json,result,created_at)
		VALUES (?, 'test', 'fixture', 'batch-1', 'request-1', '{}', 'success', 0)`
	assertCount := func(want int) {
		t.Helper()
		var count int
		err := observer.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit_logs").Scan(&count)
		if err != nil || count != want {
			t.Fatalf("审计记录可见数 = %d，期望 %d，错误 %v", count, want, err)
		}
	}

	tx, err := writer.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, insert, "staged"); err != nil {
		t.Fatal(err)
	}
	assertCount(0)
	const sqliteBusy = 5
	var sqliteError *sqlite.Error
	if _, err := observer.DB.ExecContext(ctx, insert, "competing"); !errors.As(err, &sqliteError) || sqliteError.Code() != sqliteBusy {
		t.Fatalf("期望 SQLITE_BUSY，实际 %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertCount(0)
	if _, err := observer.DB.ExecContext(ctx, insert, "competing"); err != nil {
		t.Fatal(err)
	}
	assertCount(1)
}

func TestMigrateAndConstraints(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, err := Open(ctx, filepath.Join(directory, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if store.Ready(ctx) == nil {
		t.Fatal("空库错误地就绪")
	}
	for range 2 {
		if err := store.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := WritableDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`INSERT INTO users(id,username,password_hash,role,created_at) VALUES('u1','admin','hash','admin',0)`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO users(id,username,password_hash,role,created_at) VALUES('u2','other','hash','invalid',0)`,
		`INSERT INTO users(id,username,password_hash,role,created_at) VALUES('u3','admin','hash','admin',0)`,
		`INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES('token','missing',1,0)`,
	} {
		if _, err := store.DB.Exec(statement); err == nil {
			t.Fatalf("约束未生效 %s", statement)
		}
	}
	if _, err := store.DB.Exec(`UPDATE schema_migrations SET checksum = 'changed'`); err != nil {
		t.Fatal(err)
	}
	if store.Ready(ctx) == nil || store.Migrate(ctx) == nil {
		t.Fatal("迁移摘要变化未拒绝")
	}
}

func TestBatchPublicationTransactionPrototype(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "batch-prototype.db")
	writer, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	observer, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()

	// 原型仅在临时库中建表，模拟断点、批次和排队意图的共同提交。
	for _, statement := range []string{
		`CREATE TABLE prototype_cursor (source_id TEXT PRIMARY KEY, offset INTEGER NOT NULL)`,
		`CREATE TABLE prototype_batch (id TEXT PRIMARY KEY, source_id TEXT NOT NULL, generation TEXT NOT NULL,
			start_offset INTEGER NOT NULL, UNIQUE (source_id, generation, start_offset))`,
		`CREATE TABLE prototype_intent (batch_id TEXT PRIMARY KEY REFERENCES prototype_batch(id))`,
		`INSERT INTO prototype_cursor VALUES ('ssh-fixture', 0)`,
	} {
		if _, err := writer.DB.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	assertVisible := func(wantOffset, wantBatches, wantIntents int) {
		t.Helper()
		var offset, batches, intents int
		err := observer.DB.QueryRowContext(ctx, `SELECT offset, (SELECT count(*) FROM prototype_batch),
			(SELECT count(*) FROM prototype_intent) FROM prototype_cursor WHERE source_id = 'ssh-fixture'`).Scan(&offset, &batches, &intents)
		if err != nil || offset != wantOffset || batches != wantBatches || intents != wantIntents {
			t.Fatalf("观察到断点/批次/意图 = %d/%d/%d，期望 %d/%d/%d，错误 %v",
				offset, batches, intents, wantOffset, wantBatches, wantIntents, err)
		}
	}
	publish := func(intentBatchID string) error {
		t.Helper()
		tx, err := writer.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		result, err := tx.ExecContext(ctx, `UPDATE prototype_cursor SET offset = 64 WHERE source_id = 'ssh-fixture' AND offset = 0`)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			t.Fatalf("处理旧断点失败，更新 %d 行，错误 %v", rows, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO prototype_batch VALUES ('batch-1', 'ssh-fixture', 'generation-1', 0)`); err != nil {
			t.Fatal(err)
		}
		assertVisible(0, 0, 0)
		if _, err := tx.ExecContext(ctx, `INSERT INTO prototype_intent VALUES (?)`, intentBatchID); err != nil {
			return err
		}
		assertVisible(0, 0, 0)
		return tx.Commit()
	}
	var sqliteError *sqlite.Error
	const sqliteConstraintForeignKey = 787
	if err := publish("missing"); !errors.As(err, &sqliteError) || sqliteError.Code() != sqliteConstraintForeignKey {
		t.Fatalf("注入失败应触发外键约束，实际 %v", err)
	}
	assertVisible(0, 0, 0)
	if err := publish("batch-1"); err != nil {
		t.Fatal(err)
	}
	assertVisible(64, 1, 1)
	result, err := writer.DB.ExecContext(ctx, `UPDATE prototype_cursor SET offset = 128 WHERE source_id = 'ssh-fixture' AND offset = 0`)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 0 {
		t.Fatalf("提交后旧断点应失效，更新 %d 行，错误 %v", rows, err)
	}
	assertVisible(64, 1, 1)
}
