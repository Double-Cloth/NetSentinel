package repository

import (
	"context"
	"path/filepath"
	"testing"
)

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
