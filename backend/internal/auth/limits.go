package auth

import (
	"sync"
	"time"
)

type loginLimits struct {
	mu     sync.Mutex
	start  time.Time
	counts map[string]int
}

func (l *loginLimits) allow(ip, username string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.start) >= time.Minute {
		l.start = now
		l.counts = make(map[string]int)
	}
	ipKey, userKey := "ip:"+ip, "user:"+username
	if len(l.counts) >= 4096 || l.counts[ipKey] >= 120 || l.counts[userKey] >= 10 {
		return false
	}
	l.counts[ipKey]++
	l.counts[userKey]++
	return true
}
