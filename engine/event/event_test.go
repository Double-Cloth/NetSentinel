package event

import "testing"

func TestHTTPEventAndFields(t *testing.T) {
	bytesSent := int64(42)
	e := Event{SchemaVersion: 1, ID: "event-1", Index: 1, DatasetID: "dataset-1", Source: "nginx", SourceHost: "srv-a", Kind: "http.access", SrcIP: "2001:db8::1", HTTP: &HTTP{Method: "GET", Path: "/%61", Status: 404, BytesSent: &bytesSent}, RawRef: RawRef{FileID: "file-1", LineNo: 1, RawHash: "raw-1"}}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	for field, expected := range map[string]any{"http.method": "GET", "http.path": "/%61", "http.status": int64(404), "http.bytes_sent": int64(42), "source_host": "srv-a", "src_ip": "2001:db8::1"} {
		value, exists := e.Field(field)
		if !exists || value != expected {
			t.Fatalf("字段 %s 不符 %v", field, value)
		}
		if FieldType("nginx", field) == "" {
			t.Fatalf("字段类型缺失 %s", field)
		}
	}
	for _, change := range []func(*Event){
		func(e *Event) { e.SchemaVersion = 2 },
		func(e *Event) { e.TimeUS = 253402300800000000 },
		func(e *Event) { e.Source = "other" },
		func(e *Event) { e.SrcIP = "::ffff:192.0.2.1" },
		func(e *Event) { e.HTTP = nil },
		func(e *Event) { value := int64(-1); copy := *e.HTTP; copy.BytesSent = &value; e.HTTP = &copy },
	} {
		copy := e
		change(&copy)
		if copy.Validate() == nil {
			t.Fatalf("无效事件被接受 %+v", copy)
		}
	}
}
