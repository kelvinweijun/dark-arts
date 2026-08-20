package mesh

import (
	"testing"
	"time"
)

func TestRouterRoundRobin(t *testing.T) {
	r := NewRouter("a", "b", "c")
	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		addr, ok := r.Next()
		if !ok {
			t.Fatal("expected peer")
		}
		seen[addr]++
	}
	for _, p := range []string{"a", "b", "c"} {
		if seen[p] != 3 {
			t.Fatalf("round robin uneven: %v", seen)
		}
	}
}

func TestRouterMarkDownSkips(t *testing.T) {
	r := NewRouter("a", "b")
	r.MarkDown("a", 10*time.Minute)
	got := map[string]bool{}
	for i := 0; i < 4; i++ {
		addr, _ := r.Next()
		got[addr] = true
		if addr == "a" {
			t.Fatal("marked-down peer must be skipped")
		}
	}
	if !got["b"] {
		t.Fatal("healthy peer must be used")
	}
	if !r.IsDown("a") {
		t.Fatal("a must be down")
	}
}

func TestRouterMarkDownExpires(t *testing.T) {
	r := NewRouter("a")
	r.MarkDown("a", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if r.IsDown("a") {
		t.Fatal("down state must expire")
	}
	if _, ok := r.Next(); !ok {
		t.Fatal("peer must be usable after expiry")
	}
}

func TestRouterAllDown(t *testing.T) {
	r := NewRouter("a", "b")
	r.MarkDown("a", time.Hour)
	r.MarkDown("b", time.Hour)
	if _, ok := r.Next(); ok {
		t.Fatal("all-down router must return no peer")
	}
}

func TestRouterAddRemove(t *testing.T) {
	r := NewRouter("a")
	r.Add("b")
	r.Add("b")
	if len(r.List()) != 2 {
		t.Fatalf("expected 2 peers, got %v", r.List())
	}
	r.Remove("a")
	if len(r.List()) != 1 || r.List()[0] != "b" {
		t.Fatalf("remove failed: %v", r.List())
	}
	if _, ok := r.Next(); !ok {
		t.Fatal("expected remaining peer")
	}
}

func TestRouterEmpty(t *testing.T) {
	r := NewRouter()
	if _, ok := r.Next(); ok {
		t.Fatal("empty router must return no peer")
	}
}
