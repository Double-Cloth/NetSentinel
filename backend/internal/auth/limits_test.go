package auth

import (
	"testing"
	"time"
)

func TestLoginLimits(t *testing.T) {
	var limits loginLimits
	now := time.Now()
	for range 10 {
		if !limits.allow("192.0.2.1", "user_1", now) {
			t.Fatal("过早触发用户名频率限制")
		}
	}
	if limits.allow("192.0.2.2", "user_1", now) {
		t.Fatal("更换 IP 后仍须限制用户名频率")
	}
	if !limits.allow("192.0.2.1", "user_1", now.Add(time.Minute)) {
		t.Fatal("窗口结束后应允许重新尝试")
	}
}
