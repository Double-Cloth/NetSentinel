// Package testfixtures 验证跨模块共享测试夹具的完整性和关键预期。
package testfixtures

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type manifest struct {
	SchemaVersion int       `json:"schema_version"`
	Fixtures      []fixture `json:"fixtures"`
}

type fixture struct {
	File                 string `json:"file"`
	Format               string `json:"format"`
	LineCount            int    `json:"line_count"`
	SHA256               string `json:"sha256"`
	Year                 int    `json:"year,omitempty"`
	Timezone             string `json:"timezone,omitempty"`
	R001ExpectedFindings int    `json:"r001_expected_findings"`
}

type failedAuth struct {
	timestamp time.Time
	group     string
}

var (
	rfc3339Line = regexp.MustCompile(`^(\S+)\s+(\S+)\s+sshd\[\d+\]:\s+Failed (?:password|publickey|keyboard-interactive) for (?:invalid user )?(\S+) from (\S+) port \d+`)
	rfc3164Line = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+Failed (?:password|publickey|keyboard-interactive) for (?:invalid user )?(\S+) from (\S+) port \d+`)
	ipv4Text    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Text    = regexp.MustCompile(`\b2001:db8:[0-9A-Fa-f:]*[0-9A-Fa-f]\b`)
	testRanges  = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
)

func TestLogFixtures(t *testing.T) {
	directory := fixtureDirectory(t)
	data, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index manifest
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	if index.SchemaVersion != 1 || len(index.Fixtures) == 0 {
		t.Fatalf("夹具清单无效：schema=%d fixtures=%d", index.SchemaVersion, len(index.Fixtures))
	}

	seen := make(map[string]bool, len(index.Fixtures))
	for _, item := range index.Fixtures {
		item := item
		t.Run(item.File, func(t *testing.T) {
			if seen[item.File] {
				t.Fatalf("夹具重复登记：%s", item.File)
			}
			seen[item.File] = true
			raw, err := os.ReadFile(filepath.Join(directory, item.File))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte("\r")) || !bytes.HasSuffix(raw, []byte("\n")) {
				t.Fatal("日志必须使用 LF 且以换行结束")
			}
			lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
			if len(lines) != item.LineCount {
				t.Fatalf("行数不符：got=%d want=%d", len(lines), item.LineCount)
			}
			digest := sha256.Sum256(raw)
			if hex.EncodeToString(digest[:]) != item.SHA256 {
				t.Fatalf("SHA-256 不符：got=%s want=%s", hex.EncodeToString(digest[:]), item.SHA256)
			}
			assertDocumentationAddresses(t, raw)
			findings := countR001Findings(t, item, raw)
			if findings != item.R001ExpectedFindings {
				t.Fatalf("R-001 预期不符：got=%d want=%d", findings, item.R001ExpectedFindings)
			}
		})
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".log" && !seen[entry.Name()] {
			t.Errorf("日志未登记到 manifest.json：%s", entry.Name())
		}
	}
}

func fixtureDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("无法定位测试源文件")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "logs"))
}

func assertDocumentationAddresses(t *testing.T, raw []byte) {
	t.Helper()
	addresses := append(ipv4Text.FindAllString(string(raw), -1), ipv6Text.FindAllString(string(raw), -1)...)
	for _, text := range addresses {
		address, err := netip.ParseAddr(text)
		if err != nil {
			t.Fatalf("IP 地址无效：%s", text)
		}
		allowed := false
		for _, prefix := range testRanges {
			if prefix.Contains(address) {
				allowed = true
				break
			}
		}
		if !allowed {
			t.Errorf("夹具使用了非文档网段地址：%s", text)
		}
	}
}

func countR001Findings(t *testing.T, item fixture, raw []byte) int {
	t.Helper()
	if !strings.HasPrefix(item.Format, "ssh-") {
		return 0
	}
	var events []failedAuth
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		if event, ok := parseFailedAuth(t, item, scanner.Text()); ok {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].timestamp.Before(events[j].timestamp) })
	windows := make(map[string][]time.Time)
	armed := make(map[string]bool)
	findings := 0
	for _, event := range events {
		window := windows[event.group]
		left := event.timestamp.Add(-300 * time.Second)
		for len(window) > 0 && window[0].Before(left) {
			window = window[1:]
		}
		if len(window) < 4 {
			armed[event.group] = true
		}
		window = append(window, event.timestamp)
		if len(window) >= 5 && armed[event.group] {
			findings++
			armed[event.group] = false
		}
		windows[event.group] = window
	}
	return findings
}

func parseFailedAuth(t *testing.T, item fixture, line string) (failedAuth, bool) {
	t.Helper()
	var match []string
	var timestamp time.Time
	var err error
	switch item.Format {
	case "ssh-rfc3339":
		match = rfc3339Line.FindStringSubmatch(line)
		if match == nil {
			return failedAuth{}, false
		}
		timestamp, err = time.Parse(time.RFC3339Nano, match[1])
	case "ssh-rfc3164":
		match = rfc3164Line.FindStringSubmatch(line)
		if match == nil {
			return failedAuth{}, false
		}
		location := fixedLocation(t, item.Timezone)
		timestamp, err = time.ParseInLocation("Jan 2 15:04:05 2006", fmt.Sprintf("%s %d", match[1], item.Year), location)
	default:
		t.Fatalf("不支持的 SSH 夹具格式：%s", item.Format)
	}
	if err != nil {
		return failedAuth{}, false
	}
	address, err := netip.ParseAddr(match[4])
	if err != nil {
		return failedAuth{}, false
	}
	return failedAuth{timestamp: timestamp, group: strings.Join([]string{match[2], address.String(), match[3]}, "\x00")}, true
}

func fixedLocation(t *testing.T, value string) *time.Location {
	t.Helper()
	if len(value) != 6 || (value[0] != '+' && value[0] != '-') || value[3] != ':' {
		t.Fatalf("RFC3164 时区参数无效：%q", value)
	}
	hours, errHours := strconv.Atoi(value[1:3])
	minutes, errMinutes := strconv.Atoi(value[4:6])
	if errHours != nil || errMinutes != nil || hours > 23 || minutes > 59 {
		t.Fatalf("RFC3164 时区参数无效：%q", value)
	}
	offset := (hours*60 + minutes) * 60
	if value[0] == '-' {
		offset = -offset
	}
	return time.FixedZone(value, offset)
}
