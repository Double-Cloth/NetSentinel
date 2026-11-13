// Package predicate 编译并执行有界、带类型的事件过滤表达式。
package predicate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Double-Cloth/NetSentinel/engine/event"
)

type Error struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + " " + e.Path + " " + e.Message }

type Node struct {
	All   []Node          `json:"all,omitempty"`
	Any   []Node          `json:"any,omitempty"`
	Field string          `json:"field,omitempty"`
	Op    string          `json:"op,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

type Matcher func(event.Event) bool

// Compile 会规范化独占节点树，返回的闭包仅捕获不可变数据。
func Compile(node *Node, source string) (Matcher, error) {
	count := 0
	return compile(node, source, "/where", 1, &count)
}

func compile(node *Node, source, path string, depth int, count *int) (Matcher, error) {
	*count = *count + 1
	if depth > 4 || *count > 64 {
		return nil, invalid("RULE_LIMIT_EXCEEDED", path, "表达式深度或节点数超限")
	}
	branches := 0
	if node.All != nil {
		branches++
	}
	if node.Any != nil {
		branches++
	}
	if node.Field != "" || node.Op != "" || node.Value != nil {
		branches++
	}
	if branches != 1 {
		return nil, invalid("RULE_SCHEMA_INVALID", path, "表达式须为一种节点")
	}
	if node.All != nil || node.Any != nil {
		children, name := node.All, "all"
		if node.Any != nil {
			children, name = node.Any, "any"
		}
		if len(children) == 0 {
			return nil, invalid("RULE_SCHEMA_INVALID", path, "子表达式不能为空")
		}
		matchers := make([]Matcher, 0, len(children))
		for i := range children {
			matcher, err := compile(&children[i], source, fmt.Sprintf("%s/%s/%d", path, name, i), depth+1, count)
			if err != nil {
				return nil, err
			}
			matchers = append(matchers, matcher)
		}
		return func(e event.Event) bool {
			for _, matcher := range matchers {
				matched := matcher(e)
				if name == "all" && !matched {
					return false
				}
				if name == "any" && matched {
					return true
				}
			}
			return name == "all"
		}, nil
	}
	typ := event.FieldType(source, node.Field)
	if typ == "" {
		return nil, invalid("RULE_FIELD_UNKNOWN", path+"/field", "字段未知或与来源不兼容")
	}
	field, op := node.Field, node.Op
	if op == "exists" {
		value, err := scalar(node.Value, "boolean", field)
		if err != nil {
			return nil, invalid("RULE_VALUE_TYPE", path+"/value", err.Error())
		}
		return func(e event.Event) bool { _, exists := e.Field(field); return exists == value.(bool) }, nil
	}
	if op == "in" || op == "not_in" {
		if typ == "boolean" {
			return nil, invalid("RULE_VALUE_TYPE", path+"/value", "集合比较支持 string 或 integer")
		}
		var entries []json.RawMessage
		if json.Unmarshal(node.Value, &entries) != nil || len(entries) == 0 || len(entries) > 100 {
			return nil, invalid("RULE_VALUE_TYPE", path+"/value", "需要包含 1—100 项的同类型数组")
		}
		values := map[any]bool{}
		for _, entry := range entries {
			value, err := scalar(entry, typ, field)
			if err != nil {
				return nil, invalid("RULE_VALUE_TYPE", path+"/value", err.Error())
			}
			values[value] = true
		}
		normalized := make([]any, 0, len(values))
		for value := range values {
			normalized = append(normalized, value)
		}
		sort.Slice(normalized, func(i, j int) bool {
			if typ == "integer" {
				return normalized[i].(int64) < normalized[j].(int64)
			}
			return normalized[i].(string) < normalized[j].(string)
		})
		node.Value, _ = json.Marshal(normalized)
		return func(e event.Event) bool {
			value, exists := e.Field(field)
			if !exists {
				return false
			}
			return values[value] == (op == "in")
		}, nil
	}
	value, err := scalar(node.Value, typ, field)
	if err != nil {
		return nil, invalid("RULE_VALUE_TYPE", path+"/value", err.Error())
	}
	switch op {
	case "eq", "neq":
		return func(e event.Event) bool {
			actual, exists := e.Field(field)
			return exists && (actual == value) == (op == "eq")
		}, nil
	case "gt", "gte", "lt", "lte":
		if typ != "integer" {
			break
		}
		return func(e event.Event) bool {
			actual, exists := e.Field(field)
			if !exists {
				return false
			}
			a, b := actual.(int64), value.(int64)
			switch op {
			case "gt":
				return a > b
			case "gte":
				return a >= b
			case "lt":
				return a < b
			default:
				return a <= b
			}
		}, nil
	case "prefix", "regex":
		if typ != "string" {
			break
		}
		text := value.(string)
		var pattern *regexp.Regexp
		if op == "regex" {
			if len(text) > 1024 {
				return nil, invalid("RULE_LIMIT_EXCEEDED", path+"/value", "正则表达式过长")
			}
			pattern, err = regexp.Compile(text)
			if err != nil {
				return nil, invalid("RULE_REGEX_INVALID", path+"/value", "正则表达式无效")
			}
		}
		return func(e event.Event) bool {
			actual, exists := e.Field(field)
			if !exists {
				return false
			}
			switch op {
			case "prefix":
				return strings.HasPrefix(actual.(string), text)
			default:
				return pattern.MatchString(actual.(string))
			}
		}, nil
	}
	return nil, invalid("RULE_SCHEMA_INVALID", path+"/op", "操作符未知或与字段类型不兼容")
}

func scalar(raw json.RawMessage, typ, field string) (any, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("比较值不能为空")
	}
	switch typ {
	case "string":
		var value string
		if json.Unmarshal(raw, &value) == nil && len(value) <= 8192 {
			return value, nil
		}
	case "integer":
		var value int64
		if json.Unmarshal(raw, &value) == nil {
			if field == "http.status" && (value < 100 || value > 599) {
				return nil, fmt.Errorf("HTTP 状态码需要位于 100—599")
			}
			return value, nil
		}
	case "boolean":
		var value bool
		if json.Unmarshal(raw, &value) == nil {
			return value, nil
		}
	}
	return nil, fmt.Errorf("比较值需要 %s 类型", typ)
}

func invalid(code, path, message string) error {
	return &Error{Code: code, Path: path, Message: message}
}
