package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/Double-Cloth/NetSentinel/engine/event"
	"github.com/Double-Cloth/NetSentinel/engine/finding"
	"github.com/Double-Cloth/NetSentinel/engine/rule"
	engine "github.com/Double-Cloth/NetSentinel/engine/runtime"
)

type iterator struct {
	events []event.Event
	index  int
}

func (i *iterator) Next(ctx context.Context) (event.Event, bool, error) {
	if err := ctx.Err(); err != nil {
		return event.Event{}, false, err
	}
	if i.index == len(i.events) {
		return event.Event{}, false, nil
	}
	e := i.events[i.index]
	i.index++
	return e, true, nil
}

type sink struct {
	results []finding.Finding
	err     error
}

func (s *sink) Write(_ context.Context, f finding.Finding) error {
	if s.err != nil {
		return s.err
	}
	s.results = append(s.results, f)
	return nil
}

func compiled(t *testing.T) rule.CompiledRule {
	t.Helper()
	raw, err := os.ReadFile("../testdata/rules/R-001.json")
	if err != nil {
		t.Fatal(err)
	}
	sandbox, err := rule.Compile(rule.Snapshot{Spec: raw, SemanticsVersion: rule.SemanticsVersion})
	if err != nil {
		t.Fatal(err)
	}
	published, err := rule.Compile(rule.Snapshot{Spec: raw, Version: 1, SpecHash: sandbox.Config().SpecHash, SemanticsVersion: rule.SemanticsVersion})
	if err != nil {
		t.Fatal(err)
	}
	return published
}

func eventsAt(times ...int64) []event.Event {
	var events []event.Event
	for i, timestamp := range times {
		events = append(events, event.Event{SchemaVersion: 1, ID: fmt.Sprintf("event-%d", i+1), Index: int64(i + 1), DatasetID: "dataset-1", TimeUS: timestamp,
			Source: "ssh", SourceHost: "srv-a", Kind: "ssh.auth_failed", SrcIP: "192.0.2.10", User: &event.User{Name: "root"},
			RawRef: event.RawRef{FileID: "file-1", LineNo: int64(i + 1), RawHash: fmt.Sprintf("raw-%d", i+1)}})
	}
	return events
}

func TestCountGolden(t *testing.T) {
	r := compiled(t)
	cases := []struct {
		name  string
		times []int64
		hits  int
	}{
		{"TE-C01", []int64{0, 60000000, 120000000, 180000000, 240000000}, 1},
		{"TE-C02", []int64{0, 60000000, 120000000, 180000000}, 0},
		{"TE-C03", []int64{0, 60000000, 120000000, 180000000, 300000000}, 1},
		{"TE-C04", []int64{0, 60000000, 120000000, 180000000, 300000001}, 0},
		{"TE-C06", []int64{0, 1, 2, 3, 4, 5, 6}, 1},
		{"重新武装", []int64{0, 1, 2, 3, 4, 400000000, 400000001, 400000002, 400000003, 400000004}, 2},
		{"相同时间按序处理", []int64{0, 0, 0, 0, 0}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output := &sink{}
			stats, err := engine.Run(context.Background(), &iterator{events: eventsAt(tc.times...)}, []rule.CompiledRule{r}, engine.DefaultOptions(), output)
			if err != nil {
				t.Fatal(err)
			}
			if len(output.results) != tc.hits || stats.Findings != tc.hits || stats.InputEvents != len(tc.times) {
				t.Fatalf("结果与统计不符 %+v", stats)
			}
			for _, f := range output.results {
				if f.ActualCount != 5 || len(f.Evidence) != 5 || f.WindowStartUS != f.TriggerTimeUS-300000000 || f.Fingerprint == "" || f.ResultDigest == "" {
					t.Fatalf("证据不符 %+v", f)
				}
			}
		})
	}
}

func TestGroupingAndSuccess(t *testing.T) {
	r := compiled(t)
	events := eventsAt(0, 1, 2, 3, 4)
	events[3].User = &event.User{Name: "admin"}
	events[4].User = &event.User{Name: "admin"}
	output := &sink{}
	if _, err := engine.Run(context.Background(), &iterator{events: events}, []rule.CompiledRule{r}, engine.DefaultOptions(), output); err != nil || len(output.results) != 0 {
		t.Fatalf("分组隔离失败 %v", err)
	}
	events = eventsAt(0, 1, 2, 3, 4, 5)
	events[3].Kind = "ssh.auth_success"
	output = &sink{}
	if _, err := engine.Run(context.Background(), &iterator{events: events}, []rule.CompiledRule{r}, engine.DefaultOptions(), output); err != nil || len(output.results) != 1 {
		t.Fatalf("成功事件影响 Count %v", err)
	}
}

func TestInputAndFailure(t *testing.T) {
	r := compiled(t)
	cases := []struct {
		name   string
		change func([]event.Event)
		code   string
	}{
		{"重复 ID", func(e []event.Event) { e[1].ID = e[0].ID }, "INPUT_ORDER_INVALID"},
		{"索引倒退", func(e []event.Event) { e[1].Index = e[0].Index }, "INPUT_ORDER_INVALID"},
		{"时间倒退", func(e []event.Event) { e[1].TimeUS = -1 }, "INPUT_ORDER_INVALID"},
		{"数据集改变", func(e []event.Event) { e[1].DatasetID = "other" }, "INPUT_ORDER_INVALID"},
		{"来源 IP 无效", func(e []event.Event) { e[1].SrcIP = "unknown" }, "INPUT_EVENT_INVALID"},
		{"证据缺失", func(e []event.Event) { e[1].RawRef.LineNo = 0 }, "INPUT_EVENT_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := eventsAt(0, 1)
			tc.change(events)
			_, err := engine.Run(context.Background(), &iterator{events: events}, []rule.CompiledRule{r}, engine.DefaultOptions(), &sink{})
			var runErr *engine.Error
			if !errors.As(err, &runErr) || runErr.Code != tc.code {
				t.Fatalf("错误不符 %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Run(ctx, &iterator{}, []rule.CompiledRule{r}, engine.DefaultOptions(), &sink{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消失败 %v", err)
	}
	sinkError := errors.New("存储故障")
	if _, err := engine.Run(context.Background(), &iterator{events: eventsAt(0, 1, 2, 3, 4)}, []rule.CompiledRule{r}, engine.DefaultOptions(), &sink{err: sinkError}); !errors.Is(err, sinkError) {
		t.Fatalf("接收器错误丢失 %v", err)
	}
}

func TestBudgetAndExpiredGroups(t *testing.T) {
	r := compiled(t)
	options := engine.DefaultOptions()
	options.MaxBufferedRefs = 4
	_, err := engine.Run(context.Background(), &iterator{events: eventsAt(0, 1, 2, 3, 4)}, []rule.CompiledRule{r}, options, &sink{})
	var runErr *engine.Error
	if !errors.As(err, &runErr) || runErr.Code != "ENGINE_RESOURCE_LIMIT" {
		t.Fatalf("配额未生效 %v", err)
	}
	options = engine.DefaultOptions()
	options.MaxGroups = 1
	events := eventsAt(0, 400000000)
	events[1].User = &event.User{Name: "admin"}
	if _, err := engine.Run(context.Background(), &iterator{events: events}, []rule.CompiledRule{r}, options, &sink{}); err != nil {
		t.Fatalf("过期分组未释放 %v", err)
	}
}

func TestDeterministicConcurrentRuns(t *testing.T) {
	r := compiled(t)
	var results [2][]finding.Finding
	var errs [2]error
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			output := &sink{}
			_, errs[i] = engine.Run(context.Background(), &iterator{events: eventsAt(0, 1, 2, 3, 4)}, []rule.CompiledRule{r}, engine.DefaultOptions(), output)
			results[i] = output.results
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || !reflect.DeepEqual(results[0], results[1]) {
		t.Fatalf("并发结果不一致 %v", errs)
	}
	config := r.Config()
	config.GroupBy[0] = "kind"
	if r.Config().GroupBy[0] != "source_host" {
		t.Fatal("编译结果被外部修改")
	}
}
