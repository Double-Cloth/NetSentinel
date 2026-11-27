package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Double-Cloth/NetSentinel/backend/internal/auth"
	"github.com/Double-Cloth/NetSentinel/backend/internal/collection"
	"github.com/Double-Cloth/NetSentinel/backend/internal/repository"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

type appendReader struct{ data []byte }

func (reader *appendReader) Read(_ context.Context, _ collection.CatalogEntry, cursor collection.Cursor) (collection.Chunk, error) {
	remaining := reader.data[cursor.Offset:]
	end := strings.LastIndexByte(string(remaining), '\n') + 1
	return collection.Chunk{Generation: "generation-1", Bytes: append([]byte(nil), remaining[:end]...), AnchorHash: "synthetic-anchor"}, nil
}

func TestBusinessAuthenticationAndPermissions(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := repository.Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := auth.BootstrapAdmin(ctx, store.DB, "admin", "synthetic-password"); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("synthetic-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,created_at) VALUES('auditor-1','auditor',?,'auditor',1)`, string(hash)); err != nil {
		t.Fatal(err)
	}
	identity, err := auth.NewService(store.DB)
	if err != nil {
		t.Fatal(err)
	}
	catalog, _ := collection.LoadCatalog("")
	pipeline, err := collection.NewService(store.DB, catalog, nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Dependencies{Auth: identity, Collection: pipeline, PublicOrigin: "https://netsentinel.example"})
	request := func(method, path string, body []byte, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "https://netsentinel.example"+path, bytes.NewReader(body))
		req.Header.Set("Origin", "https://netsentinel.example")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if got := request("GET", "/api/v1/alerts", nil, nil, "").Code; got != 401 {
		t.Fatalf("匿名查询应返回 401，得到 %d", got)
	}
	login := func(name string) (*http.Cookie, string) {
		body, _ := json.Marshal(map[string]string{"username": name, "password": "synthetic-password"})
		out := request("POST", "/api/v1/auth/login", body, nil, "")
		if out.Code != 200 {
			t.Fatalf("登录失败: %s", out.Body.String())
		}
		var result struct {
			Data auth.Session `json:"data"`
		}
		if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return out.Result().Cookies()[0], result.Data.CSRFToken
	}
	adminCookie, adminCSRF := login("admin")
	if got := request("GET", "/api/v1/alerts", nil, adminCookie, "").Code; got != 200 {
		t.Fatalf("已登录查询应成功，得到 %d", got)
	}
	input := []byte(`{"source_ref":"missing","interval_seconds":60,"enabled":true}`)
	if got := request("POST", "/api/v1/log-sources", input, adminCookie, "").Code; got != 403 {
		t.Fatalf("缺少 CSRF 应拒绝，得到 %d", got)
	}
	if got := request("POST", "/api/v1/log-sources", input, adminCookie, adminCSRF).Code; got != 422 {
		t.Fatalf("未知授权条目应拒绝，得到 %d", got)
	}
	auditCookie, auditCSRF := login("auditor")
	if got := request("POST", "/api/v1/log-sources", input, auditCookie, auditCSRF).Code; got != 403 {
		t.Fatalf("审计员写操作应拒绝，得到 %d", got)
	}
}

func TestAutomaticBusinessChainAcrossBatches(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := repository.Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := auth.BootstrapAdmin(ctx, store.DB, "admin", "synthetic-password"); err != nil {
		t.Fatal(err)
	}
	identity, err := auth.NewService(store.DB)
	if err != nil {
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
	entry := collection.CatalogEntry{ID: "fixture", Name: "合成 SSH", Address: "127.0.0.1:2222", Username: "reader", KeyFile: "/run/fixture.key",
		HostPublicKey: string(ssh.MarshalAuthorizedKey(key)), LogPath: "/logs/auth.log", GenerationPath: "/logs/generation", Format: "ssh-rfc3339", SourceHost: "node-1"}
	catalogFile := filepath.Join(dir, "catalog.json")
	raw, _ := json.Marshal([]collection.CatalogEntry{entry})
	if err := os.WriteFile(catalogFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	catalog, err := collection.LoadCatalog(catalogFile)
	if err != nil {
		t.Fatal(err)
	}
	reader := &appendReader{}
	pipeline, err := collection.NewService(store.DB, catalog, reader, dir)
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Dependencies{Auth: identity, Collection: pipeline, PublicOrigin: "https://netsentinel.example"})
	request := func(method, path string, body []byte, cookie *http.Cookie, csrf string, expected int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "https://netsentinel.example/api/v1"+path, bytes.NewReader(body))
		req.Header.Set("Origin", "https://netsentinel.example")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code != expected {
			t.Fatalf("%s %s: %d %s", method, path, out.Code, out.Body.String())
		}
		return out
	}
	login := request("POST", "/auth/login", []byte(`{"username":"admin","password":"synthetic-password"}`), nil, "", 200)
	var session struct {
		Data auth.Session `json:"data"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]
	created := request("POST", "/log-sources", []byte(`{"source_ref":"fixture","interval_seconds":30,"enabled":true}`), cookie, session.Data.CSRFToken, 201)
	var source struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &source); err != nil {
		t.Fatal(err)
	}
	line := func(minute int) string {
		return "2026-11-26T10:0" + string(rune('0'+minute)) + ":00+08:00 node-1 sshd[21001]: Failed password for root from 192.0.2.10 port 49101 ssh2\n"
	}
	for i := 0; i < 4; i++ {
		reader.data = append(reader.data, line(i)...)
	}
	if err := pipeline.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	reader.data = append(reader.data, line(5)...)
	if _, err := store.DB.ExecContext(ctx, `UPDATE log_sources SET next_at=0 WHERE id=?`, source.Data.ID); err != nil {
		t.Fatal(err)
	}
	if err := pipeline.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	alerts := request("GET", "/alerts", nil, cookie, "", 200)
	var alertList struct {
		Data struct {
			Items []struct {
				ID      string `json:"id"`
				Finding struct {
					ActualCount int `json:"actual_count"`
				} `json:"finding"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(alerts.Body.Bytes(), &alertList); err != nil {
		t.Fatal(err)
	}
	if len(alertList.Data.Items) != 1 || alertList.Data.Items[0].Finding.ActualCount != 5 {
		t.Fatalf("跨批次告警不符: %s", alerts.Body.String())
	}
	evidence := request("GET", "/alerts/"+alertList.Data.Items[0].ID+"/evidence", nil, cookie, "", 200)
	var evidenceList struct {
		Data struct {
			Items []json.RawMessage `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(evidence.Body.Bytes(), &evidenceList); err != nil {
		t.Fatal(err)
	}
	if len(evidenceList.Data.Items) != 5 {
		t.Fatalf("证据不完整: %s", evidence.Body.String())
	}
	tasks := request("GET", "/tasks", nil, cookie, "", 200)
	var taskList struct {
		Data struct {
			Items []json.RawMessage `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(tasks.Body.Bytes(), &taskList); err != nil {
		t.Fatal(err)
	}
	if len(taskList.Data.Items) != 2 {
		t.Fatalf("自动任务数不符: %s", tasks.Body.String())
	}
}
