package rule_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Double-Cloth/NetSentinel/engine/event"
	"github.com/Double-Cloth/NetSentinel/engine/predicate"
	"github.com/Double-Cloth/NetSentinel/engine/rule"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../testdata/rules/R-001.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStrictCompile(t *testing.T) {
	raw := string(fixture(t))
	cases := []struct{ name, content, code string }{
		{"重复键", strings.Replace(raw, `"schema_version": 1`, `"schema_version": 1, "schema_version": 1`, 1), "RULE_SCHEMA_INVALID"},
		{"未知字段", strings.Replace(raw, `"threshold": 5`, `"threshold": 5, "extra": true`, 1), "RULE_SCHEMA_INVALID"},
		{"浮点阈值", strings.Replace(raw, `"threshold": 5`, `"threshold": 5.0`, 1), "RULE_SCHEMA_INVALID"},
		{"错误值类型", strings.Replace(raw, `"value": "ssh.auth_failed"`, `"value": 5`, 1), "RULE_VALUE_TYPE"},
		{"未知字段类型", strings.Replace(raw, `"field": "kind"`, `"field": "http.status"`, 1), "RULE_FIELD_UNKNOWN"},
		{"不支持检测器", strings.Replace(raw, `"type": "count"`, `"type": "distinct"`, 1), "RULE_TYPE_UNSUPPORTED"},
		{"重复分组", strings.Replace(raw, `"source_host", "src_ip"`, `"src_ip", "src_ip"`, 1), "RULE_FIELD_UNKNOWN"},
		{"窗口超限", strings.Replace(raw, `"window_seconds": 300`, `"window_seconds": 86401`, 1), "RULE_LIMIT_EXCEEDED"},
		{"额外根值", raw + `{}`, "RULE_SCHEMA_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rule.Compile(rule.Snapshot{Spec: []byte(tc.content), SemanticsVersion: rule.SemanticsVersion})
			var validation *predicate.Error
			if !errors.As(err, &validation) || validation.Code != tc.code {
				t.Fatalf("错误不符 %v", err)
			}
		})
	}
}

func TestCanonicalAndHash(t *testing.T) {
	raw := fixture(t)
	compiled, err := rule.Compile(rule.Snapshot{Spec: raw, SemanticsVersion: rule.SemanticsVersion})
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	reordered, _ := json.Marshal(object)
	other, err := rule.Compile(rule.Snapshot{Spec: reordered, Version: 1, SpecHash: compiled.Config().SpecHash, SemanticsVersion: rule.SemanticsVersion})
	if err != nil || !bytes.Equal(compiled.JSON(), other.JSON()) {
		t.Fatalf("规范化不一致 %v", err)
	}
	if _, err := rule.Compile(rule.Snapshot{Spec: raw, Version: 1, SpecHash: "changed", SemanticsVersion: rule.SemanticsVersion}); err == nil {
		t.Fatal("摘要变化未拒绝")
	}
	canonical, err := rule.CanonicalJSON(map[string]any{"b": "<>&", "a": int64(9007199254740993)})
	if err != nil || string(canonical) != `{"a":9007199254740993,"b":"<>&"}` {
		t.Fatalf("编码不符 %s %v", canonical, err)
	}
}

func TestPredicateMissingAndSets(t *testing.T) {
	for _, op := range []string{"neq", "not_in"} {
		value := `"password"`
		if op == "not_in" {
			value = `["password"]`
		}
		node := predicate.Node{Field: "ssh.auth_method", Op: op, Value: json.RawMessage(value)}
		match, err := predicate.Compile(&node, "ssh")
		if err != nil || match(event.Event{}) {
			t.Fatalf("缺失值语义错误 %v", err)
		}
	}
	node := predicate.Node{Field: "kind", Op: "in", Value: json.RawMessage(`["z","a","a"]`)}
	match, err := predicate.Compile(&node, "ssh")
	if err != nil || string(node.Value) != `["a","z"]` || !match(event.Event{Kind: "a"}) {
		t.Fatalf("集合规范化错误 %s %v", node.Value, err)
	}
}
