package api

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Double-Cloth/NetSentinel/backend/internal/auth"
	"github.com/Double-Cloth/NetSentinel/backend/internal/collection"
	"github.com/Double-Cloth/NetSentinel/engine/predicate"
	"github.com/Double-Cloth/NetSentinel/engine/rule"
)

func handleBusiness(w http.ResponseWriter, r *http.Request, deps Dependencies, result *response) int {
	fail := func(status int, code, message string) int {
		result.Error = &APIError{Code: code, Message: message}
		return status
	}
	if deps.Collection == nil {
		return fail(503, "BUSINESS_UNAVAILABLE", "业务服务暂不可用")
	}
	if deps.Auth == nil {
		return fail(503, "AUTH_UNAVAILABLE", "认证服务暂不可用")
	}
	token := ""
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		token = cookie.Value
	}
	session, err := deps.Auth.Current(r.Context(), token)
	if err != nil {
		if !errors.Is(err, auth.ErrSession) {
			return fail(500, "AUTH_UNAVAILABLE", "认证服务暂不可用")
		}
		return fail(401, "AUTH_REQUIRED", "请先登录")
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	if len(parts) == 0 {
		return fail(404, "NOT_FOUND", "接口不存在")
	}
	write := r.Method == http.MethodPost || r.Method == http.MethodPatch
	if write {
		origin := expectedOrigin(r, deps.PublicOrigin)
		if origin == "" || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != origin {
			return fail(403, "ORIGIN_DENIED", "请求来源不受信任")
		}
		if !hmac.Equal([]byte(session.CSRFToken), []byte(r.Header.Get("X-CSRF-Token"))) {
			return fail(403, "CSRF_INVALID", "会话验证失败")
		}
	}
	admin := session.User.Role == auth.Admin
	manager := admin || session.User.Role == auth.Analyst
	decode := func(target any) bool {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			return false
		}
		reader := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		reader.DisallowUnknownFields()
		return reader.Decode(target) == nil && reader.Decode(new(any)) == io.EOF
	}
	ctx := r.Context()
	svc := deps.Collection
	switch parts[0] {
	case "log-sources":
		if len(parts) == 2 && parts[1] == "catalog" && r.Method == http.MethodGet {
			if !admin {
				return fail(403, "FORBIDDEN", "需要管理员权限")
			}
			result.Data = map[string]any{"items": svc.CatalogItems()}
			return 200
		}
		if len(parts) == 1 && r.Method == http.MethodGet {
			items, err := svc.Sources(ctx)
			if err != nil {
				return businessError(result, err)
			}
			result.Data = map[string]any{"items": items}
			return 200
		}
		if len(parts) == 1 && r.Method == http.MethodPost {
			if !admin {
				return fail(403, "FORBIDDEN", "需要管理员权限")
			}
			var input collection.SourceInput
			if !decode(&input) {
				return fail(422, "SOURCE_CONFIG_INVALID", "来源配置格式无效")
			}
			item, err := svc.CreateSource(ctx, input, session.User.ID, result.RequestID)
			if err != nil {
				return businessError(result, err)
			}
			result.Data = item
			return 201
		}
		if len(parts) == 2 && r.Method == http.MethodGet {
			item, err := svc.Source(ctx, parts[1])
			if err != nil {
				return businessError(result, err)
			}
			result.Data = item
			return 200
		}
		if len(parts) == 2 && r.Method == http.MethodPatch {
			if !admin {
				return fail(403, "FORBIDDEN", "需要管理员权限")
			}
			var input collection.SourceInput
			if !decode(&input) {
				return fail(422, "SOURCE_CONFIG_INVALID", "来源配置格式无效")
			}
			item, err := svc.UpdateSource(ctx, parts[1], input, session.User.ID, result.RequestID)
			if err != nil {
				return businessError(result, err)
			}
			result.Data = item
			return 200
		}
		if len(parts) == 3 && parts[2] == "attempts" && r.Method == http.MethodGet {
			items, err := svc.Attempts(ctx, parts[1])
			if err != nil {
				return businessError(result, err)
			}
			result.Data = map[string]any{"items": items}
			return 200
		}
		if len(parts) == 3 && parts[2] == "retry" && r.Method == http.MethodPost {
			if !admin {
				return fail(403, "FORBIDDEN", "需要管理员权限")
			}
			id, err := svc.Retry(ctx, parts[1], session.User.ID, result.RequestID)
			if err != nil {
				return businessError(result, err)
			}
			result.Data = map[string]string{"attempt_id": id}
			return 202
		}
		if len(parts) == 3 && parts[2] == "test" && r.Method == http.MethodPost {
			if !admin {
				return fail(403, "FORBIDDEN", "需要管理员权限")
			}
			preview, err := svc.TestSource(ctx, parts[1], session.User.ID, result.RequestID)
			if err != nil {
				return fail(422, "SOURCE_TEST_FAILED", "连接测试失败，请检查授权源与服务日志")
			}
			result.Data = preview
			return 200
		}
	case "datasets":
		if len(parts) == 1 && r.Method == http.MethodGet {
			items, err := svc.Batches(ctx)
			if err != nil {
				return businessError(result, err)
			}
			result.Data = map[string]any{"items": items}
			return 200
		}
		if len(parts) == 3 && r.Method == http.MethodGet {
			if parts[2] == "events" {
				items, err := svc.Events(ctx, parts[1])
				if err != nil {
					return businessError(result, err)
				}
				result.Data = map[string]any{"items": items}
				return 200
			}
			if parts[2] == "lines" {
				items, err := svc.Lines(ctx, parts[1])
				if err != nil {
					return businessError(result, err)
				}
				result.Data = map[string]any{"items": items}
				return 200
			}
		}
	case "tasks":
		if len(parts) == 1 && r.Method == http.MethodGet {
			items, err := svc.Tasks(ctx)
			if err != nil {
				return businessError(result, err)
			}
			result.Data = map[string]any{"items": items}
			return 200
		}
		if len(parts) == 2 && r.Method == http.MethodGet {
			item, err := svc.Task(ctx, parts[1])
			if err != nil {
				return businessError(result, err)
			}
			result.Data = item
			return 200
		}
		if len(parts) == 3 && parts[2] == "retry" && r.Method == http.MethodPost {
			if !manager {
				return fail(403, "FORBIDDEN", "需要分析权限")
			}
			if err := svc.RetryTask(ctx, parts[1], session.User.ID, result.RequestID); err != nil {
				return businessError(result, err)
			}
			result.Data = map[string]string{"task_id": parts[1]}
			return 202
		}
	case "alerts":
		if len(parts) == 1 && r.Method == http.MethodGet {
			items, err := svc.Alerts(ctx)
			if err != nil {
				return businessError(result, err)
			}
			result.Data = map[string]any{"items": items}
			return 200
		}
		if len(parts) == 2 && r.Method == http.MethodGet {
			item, err := svc.Alert(ctx, parts[1])
			if err != nil {
				return businessError(result, err)
			}
			result.Data = item
			return 200
		}
		if len(parts) == 3 && parts[2] == "evidence" && r.Method == http.MethodGet {
			items, err := svc.Evidence(ctx, parts[1])
			if err != nil {
				return businessError(result, err)
			}
			result.Data = map[string]any{"items": items}
			return 200
		}
	case "rules":
		if len(parts) == 2 && parts[1] == "R-001" && r.Method == http.MethodGet {
			result.Data = svc.RuleInfo()
			return 200
		}
		if len(parts) == 2 && parts[1] == "validate" && r.Method == http.MethodPost {
			if !manager {
				return fail(403, "FORBIDDEN", "需要分析权限")
			}
			var spec json.RawMessage
			if !decode(&spec) {
				return fail(422, "RULE_SCHEMA_INVALID", "规则 JSON 无效")
			}
			compiled, err := rule.Compile(rule.Snapshot{Spec: spec, SemanticsVersion: rule.SemanticsVersion})
			if err != nil {
				var field *predicate.Error
				if errors.As(err, &field) {
					result.Error = &APIError{Code: field.Code, Message: field.Message, Details: []FieldError{{Path: field.Path, Message: field.Message}}}
					return 422
				}
				return fail(422, "RULE_INVALID", "规则校验失败")
			}
			result.Data = map[string]any{"spec_hash": compiled.Config().SpecHash, "canonical_spec": json.RawMessage(compiled.JSON())}
			return 200
		}
	}
	if r.Method != http.MethodGet && !write {
		return fail(405, "METHOD_NOT_ALLOWED", "请求方法不受支持")
	}
	return fail(404, "NOT_FOUND", "接口不存在或查询失败")
}

func businessError(result *response, err error) int {
	var field *collection.InputError
	if errors.As(err, &field) {
		result.Error = &APIError{Code: "INPUT_INVALID", Message: field.Message, Details: []FieldError{{Path: field.Path, Message: field.Message}}}
		return 422
	}
	switch {
	case errors.Is(err, collection.ErrNotFound):
		result.Error = &APIError{Code: "NOT_FOUND", Message: "对象不存在"}
		return 404
	case errors.Is(err, collection.ErrConflict):
		result.Error = &APIError{Code: "VERSION_CONFLICT", Message: "对象版本或状态冲突，请刷新后重试"}
		return 409
	case errors.Is(err, collection.ErrInvalid):
		result.Error = &APIError{Code: "INPUT_INVALID", Message: "输入参数不符合授权或格式约束"}
		return 422
	default:
		result.Error = &APIError{Code: "INTERNAL_ERROR", Message: "服务处理失败，请稍后重试"}
		return 500
	}
}
