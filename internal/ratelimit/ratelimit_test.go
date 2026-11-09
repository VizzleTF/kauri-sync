package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(60)
	l.now = func() time.Time { return now }

	for i := range 60 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("request %d of the burst refused", i)
		}
	}
	ok, wait := l.Allow("a")
	if ok || wait != time.Second {
		t.Fatalf("over the limit: allowed %v, wait %v; want refused, 1s", ok, wait)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("another key shares the limit")
	}

	now = now.Add(time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("refilled token refused")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("more than one token refilled in a second")
	}
}

func TestLimiterSweepsIdleKeys(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(60)
	l.now = func() time.Time { return now }
	l.Allow("a")
	now = now.Add(sweepInterval + time.Minute)
	l.Allow("b")
	if _, ok := l.buckets["a"]; ok {
		t.Fatal("idle bucket kept")
	}
}

func TestNilLimiterAllows(t *testing.T) {
	l := New(0)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("disabled limiter refused")
	}
}
