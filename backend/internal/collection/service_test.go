package collection

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Double-Cloth/NetSentinel/backend/internal/repository"
	"golang.org/x/crypto/ssh"
)

type fakeReader struct {
	data []byte
	fail bool
}

func (f *fakeReader) Read(_ context.Context, _ CatalogEntry, cursor Cursor) (Chunk, error) {
	if f.fail {
		return Chunk{}, errors.New("合成断线")
	}
	if cursor.Offset > int64(len(f.data)) {
		return Chunk{}, errors.New("截断")
	}
	if cursor.Offset > 0 {
		start := max(int64(0), cursor.Offset-4096)
		if hash(f.data[start:cursor.Offset]) != cursor.AnchorHash {
			return Chunk{}, errors.New("锚点不匹配")
		}
	}
	remaining := f.data[cursor.Offset:]
	if len(remaining) > maxRead {
		remaining = remaining[:maxRead]
	}
	end := strings.LastIndexByte(string(remaining), '\n') + 1
	consumed := remaining[:end]
	newOffset := cursor.Offset + int64(end)
	start := max(int64(0), newOffset-4096)
	return Chunk{Generation: "generation-1", Bytes: append([]byte(nil), consumed...), AnchorHash: hash(f.data[start:newOffset]), Backlog: int64(len(f.data)) > newOffset}, nil
}

func testService(t *testing.T) (*Service, *fakeReader, *repository.Store, string) {
	t.Helper()
	ctx := context.Background()
	store, err := repository.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	entry := CatalogEntry{ID: "fixture", Name: "合成 SSH", Address: "127.0.0.1:2222", Username: "reader", KeyFile: "/run/fixture.key",
		HostPublicKey: string(ssh.MarshalAuthorizedKey(key)), LogPath: "/logs/auth.log", GenerationPath: "/logs/generation", Format: "ssh-rfc3339", SourceHost: "node-1"}
	file := filepath.Join(t.TempDir(), "catalog.json")
	raw, _ := json.Marshal([]CatalogEntry{entry})
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	catalog, err := LoadCatalog(file)
	if err != nil {
		t.Fatal(err)
	}
	reader := &fakeReader{}
	svc, err := NewService(store.DB, catalog, reader, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, err := svc.CreateSource(ctx, SourceInput{CatalogID: "fixture", IntervalSeconds: 60, Enabled: true}, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	return svc, reader, store, source.ID
}

func sshLine(minute int) string {
	return "2026-11-26T10:" + []string{"00", "01", "02", "03", "04", "05"}[minute] + ":00+08:00 node-1 sshd[21001]: Failed password for root from 192.0.2.10 port 49101 ssh2\n"
}

func TestCrossBatchCountAndReplay(t *testing.T) {
	ctx := context.Background()
	svc, reader, store, sourceID := testService(t)
	for i := 0; i < 4; i++ {
		reader.data = append(reader.data, sshLine(i)...)
	}
	if err := svc.Collect(ctx, sourceID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RunQueuedTasks(ctx); err != nil {
		t.Fatal(err)
	}
	alerts, err := svc.Alerts(ctx)
	if err != nil || len(alerts) != 0 {
		t.Fatalf("前四条不应告警: %v %v", alerts, err)
	}
	reader.data = append(reader.data, sshLine(5)...)
	if err := svc.Collect(ctx, sourceID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RunQueuedTasks(ctx); err != nil {
		t.Fatal(err)
	}
	alerts, err = svc.Alerts(ctx)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("跨批次应有一条告警: %d %v", len(alerts), err)
	}
	if alerts[0].Finding.ActualCount != 5 {
		t.Fatalf("证据计数 %d", alerts[0].Finding.ActualCount)
	}
	evidence, err := svc.Evidence(ctx, alerts[0].ID)
	if err != nil || len(evidence) != 5 {
		t.Fatalf("跨批次证据不完整: %d %v", len(evidence), err)
	}
	for i := 1; i < len(evidence); i++ {
		if evidence[i].RawRef.LineNo <= evidence[i-1].RawRef.LineNo {
			t.Fatal("证据顺序错误")
		}
	}
	if _, err := store.DB.ExecContext(ctx, `UPDATE alerts SET status='false_positive' WHERE id=?`, alerts[0].ID); err != nil {
		t.Fatal(err)
	}
	reader.data = append(reader.data, strings.Replace(strings.Replace(sshLine(5), "10:05:", "10:06:", 1), "Failed", "Accepted", 1)...)
	if err := svc.Collect(ctx, sourceID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RunQueuedTasks(ctx); err != nil {
		t.Fatal(err)
	}
	if later, err := svc.Alerts(ctx); err != nil || len(later) != 1 {
		t.Fatalf("新批次重复告警: %d %v", len(later), err)
	}
	if _, err := store.DB.ExecContext(ctx, `UPDATE analysis_tasks SET status='queued' WHERE batch_id=?`, alerts[0].BatchID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RunQueuedTasks(ctx); err != nil {
		t.Fatal(err)
	}
	again, err := svc.Alerts(ctx)
	if err != nil || len(again) != 1 || again[0].Status != "false_positive" {
		t.Fatalf("重跑覆盖了历史: %+v %v", again, err)
	}
	if err := svc.Collect(ctx, sourceID); err != nil {
		t.Fatal(err)
	}
	if batches, err := svc.Batches(ctx); err != nil || len(batches) != 3 {
		t.Fatalf("空读创建了批次: %d %v", len(batches), err)
	}
}

func TestHalfLineAndFailureKeepCursor(t *testing.T) {
	ctx := context.Background()
	svc, reader, _, sourceID := testService(t)
	reader.data = []byte(strings.TrimSuffix(sshLine(0), "\n"))
	if err := svc.Collect(ctx, sourceID); err != nil {
		t.Fatal(err)
	}
	source, err := svc.Source(ctx, sourceID)
	if err != nil || source.ByteOffset != 0 || source.Health != "backlog" {
		t.Fatalf("半行推进了断点或未标识积压: %+v %v", source, err)
	}
	reader.data = append(reader.data, '\n')
	if err := svc.Collect(ctx, sourceID); err != nil {
		t.Fatal(err)
	}
	source, err = svc.Source(ctx, sourceID)
	if err != nil || source.ByteOffset != int64(len(reader.data)) {
		t.Fatalf("完整行断点错误: %+v %v", source, err)
	}
	reader.fail = true
	if err := svc.Collect(ctx, sourceID); err == nil {
		t.Fatal("断线应失败")
	}
	failed, err := svc.Source(ctx, sourceID)
	if err != nil || failed.ByteOffset != source.ByteOffset || failed.Health != "failed" {
		t.Fatalf("断线改变断点或未显示失败: %+v %v", failed, err)
	}
}

func TestLateEventKeepsPublishedPrefix(t *testing.T) {
	ctx := context.Background()
	svc, reader, _, sourceID := testService(t)
	reader.data = []byte(sshLine(5))
	if err := svc.Collect(ctx, sourceID); err != nil {
		t.Fatal(err)
	}
	before, err := svc.Source(ctx, sourceID)
	if err != nil {
		t.Fatal(err)
	}
	reader.data = append(reader.data, sshLine(0)...)
	if err := svc.Collect(ctx, sourceID); err == nil {
		t.Fatal("晚到事件应被拒绝")
	}
	after, err := svc.Source(ctx, sourceID)
	if err != nil || after.ByteOffset != before.ByteOffset || after.Health != "failed" {
		t.Fatalf("晚到事件改变已发布前缀: %+v %v", after, err)
	}
	batches, err := svc.Batches(ctx)
	if err != nil || len(batches) != 1 {
		t.Fatalf("晚到事件发布了批次: %+v %v", batches, err)
	}
}

func TestCatalogChangeShowsSourceFailure(t *testing.T) {
	ctx := context.Background()
	svc, _, _, sourceID := testService(t)
	entry, _ := svc.catalog.Get("fixture")
	entry.LogPath = "/logs/other.log"
	svc.catalog.entries["fixture"] = entry
	if err := svc.Collect(ctx, sourceID); err == nil {
		t.Fatal("授权源目录变化应阻止采集")
	}
	source, err := svc.Source(ctx, sourceID)
	if err != nil || source.Health != "failed" {
		t.Fatalf("授权源目录变化未显示失败: %+v %v", source, err)
	}
	attempts, err := svc.Attempts(ctx, sourceID)
	if err != nil || len(attempts) != 1 || attempts[0].ErrorCode != "SOURCE_CATALOG_CHANGED" {
		t.Fatalf("授权源目录变化未记录尝试: %+v %v", attempts, err)
	}
}

func TestParsers(t *testing.T) {
	sshEvent, kind, _ := ParseLine(ParseConfig{Format: "ssh-rfc3339", SourceHost: "node-1"}, strings.TrimSpace(sshLine(0)))
	if kind != "event" || sshEvent.Kind != "ssh.auth_failed" || sshEvent.User.Name != "root" {
		t.Fatalf("SSH 解析错误 %+v %s", sshEvent, kind)
	}
	nginxEvent, kind, _ := ParseLine(ParseConfig{Format: "nginx-combined", SourceHost: "web-1"}, `192.0.2.70 - - [26/Nov/2026:16:00:00 +0800] "GET /index.html HTTP/1.1" 200 4520 "-" "synthetic"`)
	if kind != "event" || nginxEvent.HTTP.Path != "/index.html" || nginxEvent.HTTP.Status != 200 {
		t.Fatalf("Nginx 解析错误 %+v %s", nginxEvent, kind)
	}
}

func TestPublicationRollbackKeepsCursor(t *testing.T) {
	ctx := context.Background()
	svc, reader, store, sourceID := testService(t)
	reader.data = []byte(sshLine(0))
	if _, err := store.DB.ExecContext(ctx, `CREATE TRIGGER reject_task BEFORE INSERT ON analysis_tasks BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Collect(ctx, sourceID); err == nil {
		t.Fatal("故障注入应使发布失败")
	}
	source, err := svc.Source(ctx, sourceID)
	if err != nil || source.ByteOffset != 0 || source.Health != "failed" {
		t.Fatalf("失败后断点或状态错误: %+v %v", source, err)
	}
	batches, err := svc.Batches(ctx)
	if err != nil || len(batches) != 0 {
		t.Fatalf("失败留下正式批次: %d %v", len(batches), err)
	}
	files, err := os.ReadDir(filepath.Join(svc.dataDir, "raw"))
	if err != nil || len(files) != 0 {
		t.Fatalf("失败留下原文对象: %d %v", len(files), err)
	}
	if _, err := store.DB.ExecContext(ctx, `DROP TRIGGER reject_task`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Collect(ctx, sourceID); err != nil {
		t.Fatalf("故障消除后无法续采: %v", err)
	}
}

func TestRecoverDetectsModifiedPublishedRaw(t *testing.T) {
	ctx := context.Background()
	svc, reader, store, sourceID := testService(t)
	reader.data = []byte(sshLine(0))
	if err := svc.Collect(ctx, sourceID); err != nil {
		t.Fatal(err)
	}
	var relative string
	if err := store.DB.QueryRowContext(ctx, `SELECT raw_path FROM raw_batches LIMIT 1`).Scan(&relative); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(svc.dataDir, relative)
	modified := append([]byte(nil), reader.data...)
	modified[0] = '1'
	if err := os.WriteFile(full, modified, 0600); err != nil {
		t.Fatal(err)
	}
	if err := svc.Recover(ctx); err == nil {
		t.Fatal("已发布原文被修改时启动恢复应失败")
	}
}
