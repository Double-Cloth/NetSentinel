// Package api 提供统一响应、请求标识和基础健康检查。
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/Double-Cloth/NetSentinel/engine/rule"
)

type Dependencies struct {
	DatabaseReady  func(context.Context) error
	DirectoryReady func() error
	Logger         *slog.Logger
}

type Health struct {
	Status           string            `json:"status"`
	Checks           map[string]string `json:"checks,omitempty"`
	SemanticsVersion string            `json:"engine_semantics_version,omitempty"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type response struct {
	Data      any       `json:"data,omitempty"`
	Error     *APIError `json:"error,omitempty"`
	RequestID string    `json:"request_id"`
}

func New(deps Dependencies) http.Handler {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			http.Error(w, "请求标识生成失败", http.StatusInternalServerError)
			return
		}
		requestID := hex.EncodeToString(id)
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		status := http.StatusOK
		result := response{RequestID: requestID}
		switch r.URL.Path {
		case "/api/v1/health/live", "/api/v1/health/ready":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				status = http.StatusMethodNotAllowed
				w.Header().Set("Allow", "GET, HEAD")
				result.Error = &APIError{Code: "METHOD_NOT_ALLOWED", Message: "请求方法不受支持"}
				break
			}
			health := Health{Status: "ok"}
			if r.URL.Path == "/api/v1/health/ready" {
				ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
				defer cancel()
				health.Checks = map[string]string{"api": "ready", "database": "ready", "directory": "ready"}
				health.SemanticsVersion = rule.SemanticsVersion
				if deps.DatabaseReady == nil || deps.DatabaseReady(ctx) != nil {
					health.Checks["database"] = "unavailable"
					status = http.StatusServiceUnavailable
				}
				if deps.DirectoryReady == nil || deps.DirectoryReady() != nil {
					health.Checks["directory"] = "unavailable"
					status = http.StatusServiceUnavailable
				}
				if status != http.StatusOK {
					health.Status = "unavailable"
				}
			}
			result.Data = health
		default:
			status = http.StatusNotFound
			result.Error = &APIError{Code: "NOT_FOUND", Message: "请求的接口不存在"}
		}
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			if err := json.NewEncoder(w).Encode(result); err != nil {
				deps.Logger.Error("响应写入失败", "request_id", requestID)
			}
		}
		deps.Logger.Info("HTTP 请求完成", "request_id", requestID, "method", r.Method, "status", status, "duration_ms", time.Since(start).Milliseconds())
	})
}
