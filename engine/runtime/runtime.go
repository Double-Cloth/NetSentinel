// Package runtime 通过迭代器和接收器执行确定性的离线分析。
package runtime

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/Double-Cloth/NetSentinel/engine/detector"
	"github.com/Double-Cloth/NetSentinel/engine/event"
	"github.com/Double-Cloth/NetSentinel/engine/finding"
	"github.com/Double-Cloth/NetSentinel/engine/rule"
)

type EventIterator interface {
	Next(context.Context) (event.Event, bool, error)
}
type FindingSink interface {
	Write(context.Context, finding.Finding) error
}

type RunOptions struct {
	MaxEvents, MaxGroups, MaxBufferedRefs, MaxStateBytes, MaxFindings, MaxEvidenceRefs int
}

func DefaultOptions() RunOptions {
	return RunOptions{MaxEvents: 1000000, MaxGroups: 20000, MaxBufferedRefs: 200000, MaxStateBytes: 64 * 1024 * 1024, MaxFindings: 50000, MaxEvidenceRefs: 1000000}
}

type RuleStats struct {
	EvaluatedEvents     int `json:"evaluated_events"`
	MatchedEvents       int `json:"matched_events"`
	SkippedMissingGroup int `json:"skipped_missing_group"`
	Findings            int `json:"findings"`
}

type RunStats struct {
	InputEvents      int                   `json:"input_events"`
	Findings         int                   `json:"findings"`
	EvidenceRefs     int                   `json:"evidence_refs"`
	PeakGroups       int                   `json:"peak_groups"`
	PeakBufferedRefs int                   `json:"peak_buffered_refs"`
	Elapsed          time.Duration         `json:"engine_elapsed_ns"`
	Rules            map[string]*RuleStats `json:"rules"`
}

type Error struct {
	Code  string
	Phase string
	Cause error
}

func (e *Error) Error() string { return e.Code + " " + e.Phase + ": " + e.Cause.Error() }
func (e *Error) Unwrap() error { return e.Cause }

type execution struct {
	compiled rule.CompiledRule
	config   rule.Config
	count    *detector.Count
	stats    *RuleStats
}

// Run 的接收器可以先暂存结果，调用方在成功后统一发布。
func Run(ctx context.Context, input EventIterator, rules []rule.CompiledRule, options RunOptions, sink FindingSink) (stats RunStats, err error) {
	start := time.Now()
	defer func() { stats.Elapsed = time.Since(start) }()
	stats.Rules = map[string]*RuleStats{}
	fail := func(code, phase string, cause error) error { return &Error{Code: code, Phase: phase, Cause: cause} }
	if input == nil || sink == nil || len(rules) == 0 || len(rules) > 100 {
		return stats, fail("ENGINE_CONFIG_INVALID", "initializing", fmt.Errorf("输入、输出或规则数量无效"))
	}
	for _, limit := range []int{options.MaxEvents, options.MaxGroups, options.MaxBufferedRefs, options.MaxStateBytes, options.MaxFindings, options.MaxEvidenceRefs} {
		if limit <= 0 {
			return stats, fail("ENGINE_CONFIG_INVALID", "initializing", fmt.Errorf("配额必须为正整数"))
		}
	}
	ordered := append([]rule.CompiledRule(nil), rules...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Config().RuleID < ordered[j].Config().RuleID })
	executions := make([]execution, 0, len(ordered))
	for _, compiled := range ordered {
		config := compiled.Config()
		if config.Type != "count" || stats.Rules[config.RuleID] != nil {
			return stats, fail("ENGINE_CONFIG_INVALID", "initializing", fmt.Errorf("规则无效或 ID 重复"))
		}
		ruleStats := &RuleStats{}
		stats.Rules[config.RuleID] = ruleStats
		executions = append(executions, execution{compiled: compiled, config: config, count: detector.NewCount(config), stats: ruleStats})
	}
	seen := map[string]bool{}
	seenBytes := 0
	var previous event.Event
	for {
		if err := ctx.Err(); err != nil {
			return stats, fail("ENGINE_CANCELED", "reading", err)
		}
		e, exists, err := input.Next(ctx)
		if err != nil {
			return stats, fail("ENGINE_INPUT_FAILED", "reading", err)
		}
		if err := ctx.Err(); err != nil {
			return stats, fail("ENGINE_CANCELED", "reading", err)
		}
		if !exists {
			return stats, nil
		}
		if err := e.Validate(); err != nil {
			return stats, fail("INPUT_EVENT_INVALID", "reading", err)
		}
		if seen[e.ID] || (stats.InputEvents > 0 && (e.DatasetID != previous.DatasetID || e.Index <= previous.Index || e.TimeUS < previous.TimeUS)) {
			return stats, fail("INPUT_ORDER_INVALID", "reading", fmt.Errorf("事件身份重复或输入顺序无效"))
		}
		if stats.InputEvents >= options.MaxEvents {
			return stats, fail("ENGINE_RESOURCE_LIMIT", "reading", fmt.Errorf("输入事件数超限"))
		}
		seen[e.ID] = true
		seenBytes += len(e.ID)
		previous = e
		stats.InputEvents++
		for _, run := range executions {
			if run.config.Source != e.Source {
				continue
			}
			run.stats.EvaluatedEvents++
			if !run.compiled.Match(e) {
				continue
			}
			run.stats.MatchedEvents++
			values := make([]any, 0, len(run.config.GroupBy))
			for _, field := range run.config.GroupBy {
				value, ok := e.Field(field)
				if !ok || value == "" {
					break
				}
				values = append(values, value)
			}
			if len(values) != len(run.config.GroupBy) {
				run.stats.SkippedMissingGroup++
				continue
			}
			key, err := rule.CanonicalJSON(values)
			if err != nil {
				return stats, err
			}
			result, err := run.count.Push(ctx, e, string(key), values)
			if err != nil {
				return stats, fail("ENGINE_DETECTION_FAILED", "detecting", err)
			}
			if err := checkBudget(executions, options, e.TimeUS, seenBytes, &stats); err != nil {
				return stats, err
			}
			if result == nil {
				continue
			}
			if stats.Findings >= options.MaxFindings || stats.EvidenceRefs+len(result.Evidence) > options.MaxEvidenceRefs {
				return stats, fail("ENGINE_RESOURCE_LIMIT", "detecting", fmt.Errorf("输出结果或证据数量超限"))
			}
			if err := ctx.Err(); err != nil {
				return stats, fail("ENGINE_CANCELED", "writing", err)
			}
			if err := sink.Write(ctx, *result); err != nil {
				return stats, fail("ENGINE_SINK_FAILED", "writing", err)
			}
			stats.Findings++
			stats.EvidenceRefs += len(result.Evidence)
			run.stats.Findings++
		}
		if err := checkBudget(executions, options, e.TimeUS, seenBytes, &stats); err != nil {
			return stats, err
		}
	}
}

func checkBudget(runs []execution, options RunOptions, now int64, seenBytes int, stats *RunStats) error {
	groups, refs, bytes := 0, 0, seenBytes
	for _, run := range runs {
		g, r, b := run.count.State()
		groups += g
		refs += r
		bytes += b
	}
	if groups > options.MaxGroups || refs > options.MaxBufferedRefs || bytes > options.MaxStateBytes {
		groups, refs, bytes = 0, 0, seenBytes
		for _, run := range runs {
			run.count.Prune(now)
			g, r, b := run.count.State()
			groups += g
			refs += r
			bytes += b
		}
	}
	if groups > options.MaxGroups || refs > options.MaxBufferedRefs || bytes > options.MaxStateBytes {
		return &Error{Code: "ENGINE_RESOURCE_LIMIT", Phase: "detecting", Cause: fmt.Errorf("窗口状态超限")}
	}
	stats.PeakGroups = max(stats.PeakGroups, groups)
	stats.PeakBufferedRefs = max(stats.PeakBufferedRefs, refs)
	return nil
}
