package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthAndErrors(t *testing.T) {
	for _, ready := range []bool{true, false} {
		handler := New(Dependencies{
			DatabaseReady: func(context.Context) error {
				if !ready {
					return fmt.Errorf("private/database/path")
				}
				return nil
			},
			DirectoryReady: func() error { return nil }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		for _, tc := range []struct {
			method, path string
			status       int
		}{
			{"GET", "/api/v1/health/live", 200}, {"POST", "/api/v1/health/live", 405},
			{"GET", "/api/v1/missing", 404}, {"HEAD", "/api/v1/health/live", 200},
		} {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
			if response.Code != tc.status || response.Header().Get("X-Request-ID") == "" {
				t.Fatalf("响应不符 %+v", response)
			}
			if tc.method == "HEAD" && response.Body.Len() != 0 {
				t.Fatal("HEAD 返回了正文")
			}
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/v1/health/ready", nil))
		want := 200
		if !ready {
			want = 503
		}
		if response.Code != want || strings.Contains(response.Body.String(), "private") {
			t.Fatalf("就绪检查不符 %s", response.Body.String())
		}
		var payload struct {
			Data      Health `json:"data"`
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.RequestID == "" || payload.Data.Checks["directory"] != "ready" {
			t.Fatalf("JSON 契约无效 %v", err)
		}
	}
}
