// Package event 定义与存储无关的统一事件和字段访问契约。
package event

import (
	"fmt"
	"net/netip"
)

type RawRef struct {
	FileID  string `json:"file_id"`
	LineNo  int64  `json:"line_no"`
	RawHash string `json:"raw_hash"`
}

type User struct {
	Name string `json:"name"`
}

type SSH struct {
	InvalidUser *bool  `json:"invalid_user,omitempty"`
	AuthMethod  string `json:"auth_method,omitempty"`
}

type HTTP struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int64  `json:"status"`
	BytesSent *int64 `json:"bytes_sent,omitempty"`
}

type Event struct {
	SchemaVersion int    `json:"schema_version"`
	ID            string `json:"event_id"`
	Index         int64  `json:"event_index"`
	DatasetID     string `json:"dataset_id"`
	TimeUS        int64  `json:"event_time_us"`
	Source        string `json:"source"`
	SourceHost    string `json:"source_host"`
	Kind          string `json:"kind"`
	SrcIP         string `json:"src_ip"`
	User          *User  `json:"user,omitempty"`
	SSH           *SSH   `json:"ssh,omitempty"`
	HTTP          *HTTP  `json:"http,omitempty"`
	RawRef        RawRef `json:"raw_ref"`
}

// FieldType 返回允许使用的字段类型，并检查来源兼容性。
func FieldType(source, field string) string {
	switch field {
	case "source_host", "src_ip", "kind":
		return "string"
	case "user.name", "ssh.auth_method":
		if source == "ssh" {
			return "string"
		}
	case "ssh.invalid_user":
		if source == "ssh" {
			return "boolean"
		}
	case "http.method", "http.path":
		if source == "nginx" {
			return "string"
		}
	case "http.status", "http.bytes_sent":
		if source == "nginx" {
			return "integer"
		}
	}
	return ""
}

func (e Event) Field(field string) (any, bool) {
	switch field {
	case "source_host":
		return e.SourceHost, e.SourceHost != ""
	case "src_ip":
		return e.SrcIP, e.SrcIP != ""
	case "kind":
		return e.Kind, e.Kind != ""
	case "user.name":
		if e.User != nil {
			return e.User.Name, true
		}
	case "ssh.invalid_user":
		if e.SSH != nil && e.SSH.InvalidUser != nil {
			return *e.SSH.InvalidUser, true
		}
	case "ssh.auth_method":
		if e.SSH != nil && e.SSH.AuthMethod != "" {
			return e.SSH.AuthMethod, true
		}
	case "http.method":
		if e.HTTP != nil {
			return e.HTTP.Method, true
		}
	case "http.path":
		if e.HTTP != nil {
			return e.HTTP.Path, true
		}
	case "http.status":
		if e.HTTP != nil {
			return e.HTTP.Status, true
		}
	case "http.bytes_sent":
		if e.HTTP != nil && e.HTTP.BytesSent != nil {
			return *e.HTTP.BytesSent, true
		}
	}
	return nil, false
}

func (e Event) Validate() error {
	if e.SchemaVersion != 1 || e.ID == "" || e.DatasetID == "" || e.Index < 1 || e.SourceHost == "" {
		return fmt.Errorf("INPUT_EVENT_INVALID: 缺少事件身份或来源字段")
	}
	// 限制为公历 0001—9999 年，为窗口减法预留足够空间。
	if e.TimeUS < -62135596800000000 || e.TimeUS > 253402300799999999 {
		return fmt.Errorf("INPUT_EVENT_INVALID: 事件时间超出支持范围")
	}
	ip, err := netip.ParseAddr(e.SrcIP)
	if err != nil || ip.Zone() != "" || ip.Unmap().String() != e.SrcIP {
		return fmt.Errorf("INPUT_EVENT_INVALID: 来源 IP 需要规范化")
	}
	if e.RawRef.FileID == "" || e.RawRef.LineNo < 1 || e.RawRef.RawHash == "" {
		return fmt.Errorf("INPUT_EVENT_INVALID: 缺少原始证据引用")
	}
	switch e.Source {
	case "ssh":
		if (e.Kind != "ssh.auth_failed" && e.Kind != "ssh.auth_success") || e.User == nil || e.User.Name == "" || e.HTTP != nil {
			return fmt.Errorf("INPUT_EVENT_INVALID: SSH 事件字段无效")
		}
	case "nginx":
		if e.Kind != "http.access" || e.HTTP == nil || e.HTTP.Method == "" || e.HTTP.Path == "" || e.HTTP.Status < 100 || e.HTTP.Status > 599 || e.SSH != nil {
			return fmt.Errorf("INPUT_EVENT_INVALID: HTTP 事件字段无效")
		}
		if e.HTTP.BytesSent != nil && *e.HTTP.BytesSent < 0 {
			return fmt.Errorf("INPUT_EVENT_INVALID: 响应字节数无效")
		}
	default:
		return fmt.Errorf("INPUT_EVENT_INVALID: 来源不受支持")
	}
	for _, value := range []string{e.ID, e.DatasetID, e.SourceHost, e.SrcIP, e.RawRef.FileID, e.RawRef.RawHash} {
		if len(value) > 8192 {
			return fmt.Errorf("INPUT_EVENT_INVALID: 字符串超过长度限制")
		}
	}
	for _, field := range []string{"user.name", "ssh.auth_method", "http.method", "http.path"} {
		if value, ok := e.Field(field); ok && len(value.(string)) > 8192 {
			return fmt.Errorf("INPUT_EVENT_INVALID: 字符串超过长度限制")
		}
	}
	return nil
}
