package api

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"

	"github.com/Double-Cloth/NetSentinel/backend/internal/auth"
)

const sessionCookie = "netsentinel_session"

func handleAuth(w http.ResponseWriter, r *http.Request, deps Dependencies, result *response) int {
	fail := func(status int, code, message string) int {
		result.Error = &APIError{Code: code, Message: message}
		return status
	}
	me := r.URL.Path == "/api/v1/auth/me"
	login := r.URL.Path == "/api/v1/auth/login"
	method := http.MethodPost
	if me {
		method = http.MethodGet
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		return fail(http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "请求方法不受支持")
	}
	if deps.Auth == nil {
		return fail(http.StatusServiceUnavailable, "AUTH_UNAVAILABLE", "认证服务暂不可用")
	}
	origin := expectedOrigin(r, deps.PublicOrigin)
	if !me && (origin == "" || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != origin) {
		return fail(http.StatusForbidden, "ORIGIN_DENIED", "请求来源不受信任")
	}
	cookie := &http.Cookie{
		Name: sessionCookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: strings.HasPrefix(origin, "https://"),
	}
	var token string
	if current, err := r.Cookie(sessionCookie); err == nil {
		token = current.Value
	}
	var err error
	if login {
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType != "application/json" {
			return fail(http.StatusUnsupportedMediaType, "CONTENT_TYPE_INVALID", "请使用 JSON 请求")
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			return fail(http.StatusUnprocessableEntity, "INPUT_INVALID", "请输入用户名和密码")
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		var session auth.Session
		session, cookie.Value, err = deps.Auth.Login(r.Context(), input.Username, input.Password, ip, token, result.RequestID)
		if err == nil {
			cookie.MaxAge = int(auth.SessionLifetime.Seconds())
			http.SetCookie(w, cookie)
			result.Data = session
			return http.StatusOK
		}
	} else {
		var session auth.Session
		session, err = deps.Auth.Current(r.Context(), token)
		if err == nil {
			if me {
				result.Data = session
				return http.StatusOK
			}
			if !hmac.Equal([]byte(session.CSRFToken), []byte(r.Header.Get("X-CSRF-Token"))) {
				return fail(http.StatusForbidden, "CSRF_INVALID", "会话验证失败，请刷新后重试")
			}
			err = deps.Auth.Logout(r.Context(), session.User, token, result.RequestID)
			if err == nil {
				cookie.MaxAge = -1
				http.SetCookie(w, cookie)
				return http.StatusNoContent
			}
		}
	}
	switch {
	case errors.Is(err, auth.ErrCredentials):
		return fail(http.StatusUnauthorized, "INVALID_CREDENTIALS", err.Error())
	case errors.Is(err, auth.ErrSession):
		return fail(http.StatusUnauthorized, "AUTH_REQUIRED", err.Error())
	case errors.Is(err, auth.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		return fail(http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", err.Error())
	default:
		deps.Logger.Error("认证操作失败", "request_id", result.RequestID, "error", err)
		return fail(http.StatusInternalServerError, "AUTH_UNAVAILABLE", "认证请求失败，请稍后重试")
	}
}

func expectedOrigin(r *http.Request, configured string) string {
	if configured != "" {
		return configured
	}
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if !strings.EqualFold(host, "localhost") && !ip.IsLoopback() {
		return ""
	}
	if r.TLS != nil {
		return "https://" + r.Host
	}
	return "http://" + r.Host
}
