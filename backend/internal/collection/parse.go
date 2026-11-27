package collection

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/Double-Cloth/NetSentinel/engine/event"
)

var (
	ssh3339    = regexp.MustCompile(`^(\S+)\s+(\S+)\s+sshd\[\d+\]:\s+(.+)$`)
	ssh3164    = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(\S+)\s+sshd\[\d+\]:\s+(.+)$`)
	sshFailed  = regexp.MustCompile(`^Failed \S+ for (invalid user )?(\S+) from (\S+) port \d+`)
	sshSuccess = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)
	nginx      = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+) HTTP/[0-9.]+" (\d{3}) (\d+|-) "[^"]*" "[^"]*"$`)
)

type ParseConfig struct {
	Format     string
	Year       int
	Timezone   string
	SourceHost string
}

// ParseLine 将受控格式的原始行归一化；独立 Invalid user 行不重复计数。
func ParseLine(cfg ParseConfig, line string) (event.Event, string, string) {
	line = strings.TrimSuffix(line, "\r")
	if cfg.Format == "nginx-combined" {
		match := nginx.FindStringSubmatch(line)
		if match == nil {
			return event.Event{}, "error", "NGINX_FORMAT_INVALID"
		}
		ip, err := netip.ParseAddr(match[1])
		if err != nil {
			return event.Event{}, "error", "IP_INVALID"
		}
		moment, err := time.Parse("02/Jan/2006:15:04:05 -0700", match[2])
		if err != nil {
			return event.Event{}, "error", "TIME_INVALID"
		}
		status, _ := strconv.ParseInt(match[5], 10, 64)
		if status < 100 || status > 599 {
			return event.Event{}, "error", "STATUS_INVALID"
		}
		var bytesSent *int64
		if match[6] != "-" {
			value, err := strconv.ParseInt(match[6], 10, 64)
			if err != nil {
				return event.Event{}, "error", "BYTES_INVALID"
			}
			bytesSent = &value
		}
		return event.Event{SchemaVersion: 1, TimeUS: moment.UTC().UnixMicro(), Source: "nginx", SourceHost: cfg.SourceHost,
			Kind: "http.access", SrcIP: ip.Unmap().String(), HTTP: &event.HTTP{Method: match[3], Path: match[4], Status: status, BytesSent: bytesSent}}, "event", ""
	}
	var moment time.Time
	var host, body string
	if cfg.Format == "ssh-rfc3339" {
		match := ssh3339.FindStringSubmatch(line)
		if match == nil {
			return event.Event{}, "error", "SSH_FORMAT_INVALID"
		}
		var err error
		moment, err = time.Parse(time.RFC3339Nano, match[1])
		if err != nil {
			return event.Event{}, "error", "TIME_INVALID"
		}
		host, body = match[2], match[3]
	} else if cfg.Format == "ssh-rfc3164" {
		match := ssh3164.FindStringSubmatch(line)
		if match == nil {
			return event.Event{}, "error", "SSH_FORMAT_INVALID"
		}
		if cfg.Year < 1 || cfg.Timezone == "" {
			return event.Event{}, "error", "TIME_PARAMETERS_MISSING"
		}
		location, err := time.LoadLocation(cfg.Timezone)
		if err != nil {
			return event.Event{}, "error", "TIMEZONE_INVALID"
		}
		moment, err = time.ParseInLocation("Jan 2 15:04:05 2006", fmt.Sprintf("%s %d", match[1], cfg.Year), location)
		if err != nil {
			return event.Event{}, "error", "TIME_INVALID"
		}
		host, body = match[2], match[3]
	} else {
		return event.Event{}, "error", "FORMAT_UNSUPPORTED"
	}
	if host != cfg.SourceHost {
		return event.Event{}, "error", "SOURCE_HOST_MISMATCH"
	}
	var kind, user, ipText, method string
	var invalid *bool
	if match := sshFailed.FindStringSubmatch(body); match != nil {
		kind, user, ipText = "ssh.auth_failed", match[2], match[3]
		value := match[1] != ""
		invalid = &value
		method = strings.Fields(body)[1]
	} else if match := sshSuccess.FindStringSubmatch(body); match != nil {
		kind, method, user, ipText = "ssh.auth_success", match[1], match[2], match[3]
	} else {
		return event.Event{}, "ignored", "SSH_MESSAGE_IGNORED"
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil {
		return event.Event{}, "error", "IP_INVALID"
	}
	return event.Event{SchemaVersion: 1, TimeUS: moment.UTC().UnixMicro(), Source: "ssh", SourceHost: host,
		Kind: kind, SrcIP: ip.Unmap().String(), User: &event.User{Name: user}, SSH: &event.SSH{InvalidUser: invalid, AuthMethod: method}}, "event", ""
}
