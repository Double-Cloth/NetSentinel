// Package rule 提供严格规则解码、版本核验和不可变编译结果。
package rule

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/Double-Cloth/NetSentinel/engine/event"
	"github.com/Double-Cloth/NetSentinel/engine/predicate"
)

const SemanticsVersion = "1.0.0"

type Spec struct {
	SchemaVersion int            `json:"schema_version"`
	RuleID        string         `json:"rule_id"`
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	Source        string         `json:"source"`
	Type          string         `json:"type"`
	Severity      string         `json:"severity"`
	GroupBy       []string       `json:"group_by"`
	WindowSeconds int64          `json:"window_seconds"`
	Where         predicate.Node `json:"where"`
	Threshold     int            `json:"threshold"`
}

type Snapshot struct {
	Spec             json.RawMessage `json:"spec"`
	Version          int             `json:"version"`
	SpecHash         string          `json:"spec_hash"`
	SemanticsVersion string          `json:"engine_semantics_version"`
}

type Config struct {
	RuleID, Name, Source, Type, Severity string
	GroupBy                              []string
	WindowSeconds                        int64
	Threshold, Version                   int
	SpecHash                             string
}

type CompiledRule struct {
	config  Config
	matcher predicate.Matcher
	json    []byte
}

func (c CompiledRule) Config() Config {
	config := c.config
	config.GroupBy = append([]string(nil), config.GroupBy...)
	return config
}

func (c CompiledRule) JSON() []byte             { return append([]byte(nil), c.json...) }
func (c CompiledRule) Match(e event.Event) bool { return c.matcher != nil && c.matcher(e) }

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func Compile(snapshot Snapshot) (CompiledRule, error) {
	fail := func(code, path, message string) (CompiledRule, error) {
		return CompiledRule{}, &predicate.Error{Code: code, Path: path, Message: message}
	}
	if snapshot.Version < 0 || snapshot.SemanticsVersion != SemanticsVersion {
		return fail("RULE_SCHEMA_INVALID", "/version", "规则版本或引擎语义版本无效")
	}
	if err := checkJSON(snapshot.Spec); err != nil {
		return fail("RULE_SCHEMA_INVALID", "", err.Error())
	}
	decoder := json.NewDecoder(bytes.NewReader(snapshot.Spec))
	decoder.DisallowUnknownFields()
	var spec Spec
	if err := decoder.Decode(&spec); err != nil {
		return fail("RULE_SCHEMA_INVALID", "", "规则结构或字段类型无效")
	}
	if spec.SchemaVersion != 1 || !identifier.MatchString(spec.RuleID) || strings.TrimSpace(spec.Name) == "" || len(spec.Name) > 256 || len(spec.Description) > 8192 {
		return fail("RULE_SCHEMA_INVALID", "", "规则身份、名称或结构版本无效")
	}
	if spec.Source != "ssh" && spec.Source != "nginx" {
		return fail("RULE_SCHEMA_INVALID", "/source", "来源不受支持")
	}
	if spec.Type != "count" {
		return fail("RULE_TYPE_UNSUPPORTED", "/type", "当前基础版本支持 count")
	}
	if spec.Threshold < 1 || spec.Threshold > 10000 || spec.WindowSeconds < 1 || spec.WindowSeconds > 86400 {
		return fail("RULE_LIMIT_EXCEEDED", "", "阈值或窗口超出范围")
	}
	switch spec.Severity {
	case "low", "medium", "high", "critical":
	default:
		return fail("RULE_SCHEMA_INVALID", "/severity", "严重性无效")
	}
	if len(spec.GroupBy) == 0 || len(spec.GroupBy) > 4 {
		return fail("RULE_SCHEMA_INVALID", "/group_by", "需要 1—4 个分组字段")
	}
	seen := map[string]bool{}
	allowedGroups := map[string]bool{"source_host": true, "src_ip": true, "user.name": true, "http.method": true, "http.path": true, "http.status": true}
	for _, field := range spec.GroupBy {
		typ := event.FieldType(spec.Source, field)
		if typ == "" || !allowedGroups[field] || seen[field] {
			return fail("RULE_FIELD_UNKNOWN", "/group_by", "分组字段未知、重复或类型不受支持")
		}
		seen[field] = true
	}
	matcher, err := predicate.Compile(&spec.Where, spec.Source)
	if err != nil {
		return CompiledRule{}, err
	}
	canonical, err := CanonicalJSON(spec)
	if err != nil {
		return CompiledRule{}, err
	}
	digest := sha256.Sum256(canonical)
	hash := hex.EncodeToString(digest[:])
	if (snapshot.Version > 0 && snapshot.SpecHash == "") || (snapshot.SpecHash != "" && snapshot.SpecHash != hash) {
		return fail("RULE_HASH_MISMATCH", "/spec_hash", "规则摘要与快照不一致")
	}
	return CompiledRule{config: Config{
		RuleID: spec.RuleID, Name: spec.Name, Source: spec.Source, Type: spec.Type,
		Severity: spec.Severity, GroupBy: spec.GroupBy, WindowSeconds: spec.WindowSeconds,
		Threshold: spec.Threshold, Version: snapshot.Version, SpecHash: hash,
	}, matcher: matcher, json: canonical}, nil
}
