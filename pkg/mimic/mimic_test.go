package mimic

import (
	"strings"
	"testing"
)

func TestPoolKnownPlatforms(t *testing.T) {
	for _, p := range Platforms() {
		if len(Pool(p)) == 0 {
			t.Fatalf("pool %q empty", p)
		}
		for _, ua := range Pool(p) {
			if !strings.HasPrefix(ua, "Mozilla/5.0") {
				t.Fatalf("ua %q is not a real browser UA", ua)
			}
		}
	}
}

func TestPoolFallback(t *testing.T) {
	if len(Pool("unknown-platform")) == 0 {
		t.Fatal("unknown platform must fall back to a default pool")
	}
}

func TestRotatorReturnsPoolMembers(t *testing.T) {
	r := NewRotator("windows-chrome")
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		ua := r.Next()
		if ua == "" {
			t.Fatal("empty ua")
		}
		seen[ua] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected rotation across pool, saw %d unique", len(seen))
	}
}

func TestRotatorAddDedup(t *testing.T) {
	r := NewRotator("windows-chrome")
	first := r.Next()
	r.Add(first)
	r.Add("custom-ua-1")
	found := false
	for i := 0; i < 200; i++ {
		if r.Next() == "custom-ua-1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("added ua must be rotatable")
	}
}

func TestBrowserHeaders(t *testing.T) {
	h := BrowserHeaders()
	if h.Get("Accept") == "" || h.Get("Accept-Language") == "" || h.Get("Sec-Fetch-Dest") != "document" {
		t.Fatalf("browser headers incomplete: %v", h)
	}
	if h.Get("User-Agent") != "" {
		t.Fatal("browser headers must not set a UA (rotator does)")
	}
}
