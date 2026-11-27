package collection

import (
	"bytes"
	"context"
	"time"
)

type PreviewLine struct {
	LineNo      int    `json:"line_no"`
	Disposition string `json:"disposition"`
	Diagnostic  string `json:"diagnostic"`
	EventTimeUS int64  `json:"event_time_us,omitempty"`
}

type Preview struct {
	Status     string        `json:"status"`
	Generation string        `json:"generation"`
	Lines      []PreviewLine `json:"lines"`
}

// TestSource 只读预览，不改变断点、最近成功时间或来源健康。
func (s *Service) TestSource(ctx context.Context, id, actor, requestID string) (Preview, error) {
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	source, err := s.Source(ctx, id)
	if err != nil {
		return Preview{}, err
	}
	entry, ok := s.catalog.Get(source.CatalogID)
	if !ok {
		return Preview{}, ErrInvalid
	}
	pullCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	chunk, err := s.reader.Read(pullCtx, entry, Cursor{})
	cancel()
	if err != nil {
		return Preview{}, err
	}
	result := Preview{Status: "ok", Generation: chunk.Generation, Lines: []PreviewLine{}}
	for _, raw := range bytes.SplitAfter(chunk.Bytes, []byte{'\n'}) {
		if len(raw) == 0 || len(result.Lines) >= 100 {
			break
		}
		line := string(bytes.TrimSuffix(raw, []byte{'\n'}))
		e, kind, diagnostic := ParseLine(ParseConfig{Format: source.Format, Year: source.Year, Timezone: source.Timezone, SourceHost: entry.SourceHost}, line)
		result.Lines = append(result.Lines, PreviewLine{LineNo: len(result.Lines) + 1, Disposition: kind, Diagnostic: diagnostic, EventTimeUS: e.TimeUS})
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Preview{}, err
	}
	defer tx.Rollback()
	if err := audit(ctx, tx, actor, "source.test", "log_source", id, requestID, time.Now().UTC().UnixMicro()); err != nil {
		return Preview{}, err
	}
	return result, tx.Commit()
}
