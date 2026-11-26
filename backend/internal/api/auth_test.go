package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Double-Cloth/NetSentinel/backend/internal/auth"
	"github.com/Double-Cloth/NetSentinel/backend/internal/repository"
)

func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	store, err := repository.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const correct = "synthetic-password"
	if err := auth.BootstrapAdmin(ctx, store.DB, "admin", correct); err != nil {
		t.Fatal(err)
	}
	if err := auth.BootstrapAdmin(ctx, store.DB, "another_admin", correct); err == nil {
		t.Fatal("重复初始化应失败")
	}
	identity, err := auth.NewService(store.DB)
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://netsentinel.example"
	handler := New(Dependencies{Auth: identity, PublicOrigin: origin})
	request := func(method, path, source, body, csrf string, cookie *http.Cookie, status int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, origin+"/api/v1/auth/"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if source != "" {
			r.Header.Set("Origin", source)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if rec.Code != status {
			t.Fatalf("%s %s: 状态为 %d，期望 %d", method, path, rec.Code, status)
		}
		return rec
	}
	const credentials = `{"username":"admin","password":"` + correct + `"}`
	request("GET", "me", "", "", "", nil, 401)
	request("POST", "login", "https://other.example", credentials, "", nil, 403)
	request("POST", "login", "", credentials, "", nil, 403)
	bad := request("POST", "login", origin, `{"username":"admin","password":"wrong"}`, "", nil, 401)
	unknown := request("POST", "login", origin, `{"username":"unknown","password":"wrong"}`, "", nil, 401)
	var a, b response
	if json.Unmarshal(bad.Body.Bytes(), &a) != nil || json.Unmarshal(unknown.Body.Bytes(), &b) != nil ||
		a.Error == nil || b.Error == nil || *a.Error != *b.Error {
		t.Fatal("未知用户与错误密码应返回相同错误")
	}
	login := request("POST", "login", origin, credentials, "", nil, 200)
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("会话 Cookie 属性不符")
	}
	cookie := cookies[0]
	var stored string
	if err := store.DB.QueryRow("SELECT token_hash FROM sessions").Scan(&stored); err != nil || stored == cookie.Value || len(stored) != 64 {
		t.Fatal("会话表应仅保存 SHA-256 摘要")
	}
	me := request("GET", "me", "", "", "", cookie, 200)
	var payload struct {
		Data auth.Session `json:"data"`
	}
	if err := json.Unmarshal(me.Body.Bytes(), &payload); err != nil || payload.Data.User.Role != auth.Admin || payload.Data.CSRFToken == "" {
		t.Fatal("当前会话数据不符")
	}
	request("POST", "logout", origin, "", "wrong", cookie, 403)
	request("POST", "logout", "https://other.example", "", payload.Data.CSRFToken, cookie, 403)
	if _, err := store.DB.Exec(`CREATE TRIGGER reject_logout BEFORE INSERT ON audit_logs
		WHEN NEW.action = 'auth.logout' BEGIN SELECT RAISE(ABORT, 'test fault'); END`); err != nil {
		t.Fatal(err)
	}
	request("POST", "logout", origin, "", payload.Data.CSRFToken, cookie, 500)
	request("GET", "me", "", "", "", cookie, 200)
	if _, err := store.DB.Exec("DROP TRIGGER reject_logout"); err != nil {
		t.Fatal(err)
	}
	logout := request("POST", "logout", origin, "", payload.Data.CSRFToken, cookie, 204)
	if logout.Body.Len() != 0 || len(logout.Result().Cookies()) != 1 || logout.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("注销应清除 Cookie 并返回空正文")
	}
	request("GET", "me", "", "", "", cookie, 401)
	var count int
	if err := store.DB.QueryRow("SELECT count(*) FROM audit_logs").Scan(&count); err != nil || count != 3 {
		t.Fatalf("应保存初始化、登录及注销审计，实际 %d 条，错误 %v", count, err)
	}
}
