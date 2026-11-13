// Package finding 定义不可变的检测解释、证据与稳定逻辑身份。
package finding

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/Double-Cloth/NetSentinel/engine/event"
	"github.com/Double-Cloth/NetSentinel/engine/rule"
)

type Evidence struct {
	EventID    string       `json:"event_id"`
	EventIndex int64        `json:"event_index"`
	TimeUS     int64        `json:"event_time_us"`
	RawRef     event.RawRef `json:"raw_ref"`
	StageID    string       `json:"stage_id,omitempty"`
}

type Finding struct {
	DatasetID           string     `json:"dataset_id"`
	RuleID              string     `json:"rule_id"`
	RuleVersion         int        `json:"rule_version"`
	SpecHash            string     `json:"spec_hash"`
	SemanticsVersion    string     `json:"engine_semantics_version"`
	Severity            string     `json:"severity"`
	DetectionType       string     `json:"detection_type"`
	GroupFields         []string   `json:"group_fields"`
	GroupValues         []any      `json:"group_values"`
	WindowStartUS       int64      `json:"window_start_us"`
	WindowEndUS         int64      `json:"window_end_us"`
	FirstEvidenceTimeUS int64      `json:"first_evidence_time_us"`
	LastEvidenceTimeUS  int64      `json:"last_evidence_time_us"`
	TriggerEventID      string     `json:"trigger_event_id"`
	TriggerIndex        int64      `json:"trigger_event_index"`
	TriggerTimeUS       int64      `json:"trigger_time_us"`
	ActualCount         int        `json:"actual_count"`
	Threshold           int        `json:"threshold"`
	ReasonCode          string     `json:"reason_code"`
	Evidence            []Evidence `json:"evidence"`
	Fingerprint         string     `json:"fingerprint"`
	ResultDigest        string     `json:"result_digest"`
}

func (f *Finding) Seal() error {
	identity := []any{"finding-v1", f.DatasetID, f.RuleID, f.RuleVersion, f.SpecHash, f.SemanticsVersion, f.GroupValues, f.TriggerEventID}
	raw, err := rule.CanonicalJSON(identity)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	f.Fingerprint = hex.EncodeToString(digest[:])
	f.ResultDigest = ""
	raw, err = rule.CanonicalJSON(f)
	if err != nil {
		return err
	}
	digest = sha256.Sum256(raw)
	f.ResultDigest = hex.EncodeToString(digest[:])
	return nil
}
