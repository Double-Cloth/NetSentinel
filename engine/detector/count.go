// Package detector 保存单次运行独占的窗口检测状态。
package detector

import (
	"context"

	"github.com/Double-Cloth/NetSentinel/engine/event"
	"github.com/Double-Cloth/NetSentinel/engine/finding"
	"github.com/Double-Cloth/NetSentinel/engine/rule"
)

type countGroup struct {
	values []any
	items  []finding.Evidence
	armed  bool
}

type Count struct {
	config rule.Config
	groups map[string]*countGroup
	refs   int
	bytes  int
}

func NewCount(config rule.Config) *Count {
	return &Count{config: config, groups: map[string]*countGroup{}}
}

func (c *Count) State() (groups, refs, bytes int) { return len(c.groups), c.refs, c.bytes }

func evidenceBytes(e finding.Evidence) int {
	return len(e.EventID) + len(e.RawRef.FileID) + len(e.RawRef.RawHash)
}

func (c *Count) expire(group *countGroup, cutoff int64) {
	expired := 0
	for expired < len(group.items) && group.items[expired].TimeUS < cutoff {
		c.bytes -= evidenceBytes(group.items[expired])
		group.items[expired] = finding.Evidence{}
		expired++
		c.refs--
	}
	group.items = group.items[expired:]
	if len(group.items) < c.config.Threshold {
		group.armed = true
	}
}

// Prune 在配额检查前回收其他已过期分组。
func (c *Count) Prune(now int64) {
	cutoff := now - c.config.WindowSeconds*1000000
	for key, group := range c.groups {
		c.expire(group, cutoff)
		if len(group.items) == 0 {
			delete(c.groups, key)
			c.bytes -= len(key)
		}
	}
}

func (c *Count) Push(ctx context.Context, e event.Event, key string, values []any) (*finding.Finding, error) {
	group := c.groups[key]
	if group == nil {
		group = &countGroup{values: values, armed: true}
		c.groups[key] = group
		c.bytes += len(key)
	}
	cutoff := e.TimeUS - c.config.WindowSeconds*1000000
	c.expire(group, cutoff)
	evidence := finding.Evidence{EventID: e.ID, EventIndex: e.Index, TimeUS: e.TimeUS, RawRef: e.RawRef}
	group.items = append(group.items, evidence)
	c.refs++
	c.bytes += evidenceBytes(evidence)
	if len(group.items) < c.config.Threshold || !group.armed {
		return nil, nil
	}
	group.armed = false
	result := &finding.Finding{
		DatasetID: e.DatasetID, RuleID: c.config.RuleID, RuleVersion: c.config.Version,
		SpecHash: c.config.SpecHash, SemanticsVersion: rule.SemanticsVersion,
		Severity: c.config.Severity, DetectionType: "count",
		GroupFields: append([]string(nil), c.config.GroupBy...), GroupValues: append([]any(nil), group.values...),
		WindowStartUS: cutoff, WindowEndUS: e.TimeUS, TriggerEventID: e.ID,
		FirstEvidenceTimeUS: group.items[0].TimeUS, LastEvidenceTimeUS: e.TimeUS,
		TriggerIndex: e.Index, TriggerTimeUS: e.TimeUS, ActualCount: len(group.items),
		Threshold: c.config.Threshold, ReasonCode: "COUNT_THRESHOLD_ENTERED",
		Evidence: make([]finding.Evidence, len(group.items)),
	}
	for i, item := range group.items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result.Evidence[i] = item
	}
	if err := result.Seal(); err != nil {
		return nil, err
	}
	return result, nil
}
