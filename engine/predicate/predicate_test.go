package predicate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Double-Cloth/NetSentinel/engine/event"
)

func TestOperators(t *testing.T) {
	invalidUser := true
	bytesSent := int64(100)
	ssh := event.Event{SourceHost: "srv-a", Kind: "ssh.auth_failed", User: &event.User{Name: "root"}, SSH: &event.SSH{InvalidUser: &invalidUser, AuthMethod: "password"}}
	http := event.Event{HTTP: &event.HTTP{Method: "GET", Path: "/.env", Status: 503, BytesSent: &bytesSent}}
	cases := []struct {
		source, field, op, value string
		e                        event.Event
		want                     bool
	}{
		{"ssh", "kind", "eq", `"ssh.auth_failed"`, ssh, true},
		{"ssh", "kind", "neq", `"ssh.auth_success"`, ssh, true},
		{"ssh", "ssh.invalid_user", "eq", `true`, ssh, true},
		{"ssh", "user.name", "prefix", `"ro"`, ssh, true},
		{"ssh", "user.name", "regex", `"^r.*t$"`, ssh, true},
		{"ssh", "user.name", "regex", `"^admin$"`, ssh, false},
		{"ssh", "ssh.auth_method", "in", `["publickey","password"]`, ssh, true},
		{"ssh", "ssh.auth_method", "not_in", `["publickey"]`, ssh, true},
		{"ssh", "ssh.invalid_user", "exists", `true`, ssh, true},
		{"ssh", "ssh.invalid_user", "exists", `false`, event.Event{}, true},
		{"nginx", "http.status", "gt", `500`, http, true},
		{"nginx", "http.status", "gte", `503`, http, true},
		{"nginx", "http.status", "lt", `504`, http, true},
		{"nginx", "http.status", "lte", `503`, http, true},
		{"nginx", "http.status", "in", `[500,503,503]`, http, true},
		{"nginx", "http.path", "prefix", `"/."`, http, true},
		{"nginx", "http.method", "eq", `"GET"`, http, true},
		{"nginx", "http.bytes_sent", "gte", `100`, http, true},
		{"nginx", "http.bytes_sent", "neq", `100`, event.Event{}, false},
		{"nginx", "http.path", "regex", `".*"`, event.Event{}, false},
		{"nginx", "http.status", "gt", `100`, event.Event{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.field+tc.op+tc.value, func(t *testing.T) {
			node := Node{Field: tc.field, Op: tc.op, Value: json.RawMessage(tc.value)}
			match, err := Compile(&node, tc.source)
			if err != nil || match(tc.e) != tc.want {
				t.Fatalf("操作符结果不符 %v", err)
			}
		})
	}
	node := Node{Field: "http.bytes_sent", Op: "in", Value: json.RawMessage(`[20,2,100,2]`)}
	if _, err := Compile(&node, "nginx"); err != nil || string(node.Value) != `[2,20,100]` {
		t.Fatalf("数值集合排序错误 %s %v", node.Value, err)
	}
}

func TestCombinationsAndLimits(t *testing.T) {
	leaf := Node{Field: "kind", Op: "eq", Value: json.RawMessage(`"ssh.auth_failed"`)}
	for _, node := range []Node{{All: []Node{leaf}}, {Any: []Node{leaf}}, {Any: []Node{leaf, {Field: "kind", Op: "eq", Value: json.RawMessage(`"ssh.auth_success"`)}}}} {
		match, err := Compile(&node, "ssh")
		if err != nil || !match(event.Event{Kind: "ssh.auth_failed"}) || match(event.Event{Kind: "other"}) {
			t.Fatalf("组合逻辑错误 %v", err)
		}
	}
	cases := []Node{
		{}, {All: []Node{}}, {Any: []Node{}}, {All: []Node{leaf}, Any: []Node{leaf}},
		{Field: "kind", Op: "exists", Value: json.RawMessage(`1`)},
		{Field: "kind", Op: "eq", Value: json.RawMessage(` null `)},
		{Field: "kind", Op: "unknown", Value: json.RawMessage(`"a"`)},
		{Field: "kind", Op: "gt", Value: json.RawMessage(`"a"`)},
		{Field: "kind", Op: "regex", Value: json.RawMessage(`"["`)},
		{Field: "kind", Op: "regex", Value: json.RawMessage(`"` + strings.Repeat("a", 1025) + `"`)},
		{Field: "kind", Op: "in", Value: json.RawMessage(`[]`)},
		{Field: "kind", Op: "in", Value: json.RawMessage(`["a",1]`)},
		{Field: "ssh.invalid_user", Op: "in", Value: json.RawMessage(`[true]`)},
		{Field: "ssh.invalid_user", Op: "eq", Value: json.RawMessage(`"true"`)},
	}
	deep := leaf
	for range 4 {
		deep = Node{All: []Node{deep}}
	}
	cases = append(cases, deep)
	many := Node{All: make([]Node, 64)}
	for i := range many.All {
		many.All[i] = leaf
	}
	cases = append(cases, many)
	for i, node := range cases {
		if _, err := Compile(&node, "ssh"); err == nil {
			t.Fatalf("无效表达式 %d 被接受", i)
		} else if err.Error() == "" {
			t.Fatal("缺少错误说明")
		}
	}
}
