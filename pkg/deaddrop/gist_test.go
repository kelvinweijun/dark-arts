package deaddrop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func gistServer(t *testing.T) (*httptest.Server, *fakeGistAPI) {
	t.Helper()
	api := &fakeGistAPI{gists: make(map[string]map[string]string)}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/gists":
			var req gistReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			id := "gist-" + itoa(len(api.gists)+1)
			api.gists[id] = make(map[string]string)
			for name, f := range req.Files {
				api.gists[id][name] = f.Content
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(gistResp{ID: id})
		case r.Method == http.MethodGet && len(r.URL.Path) > 7 && r.URL.Path[:7] == "/gists/":
			id := r.URL.Path[7:]
			files, ok := api.gists[id]
			if !ok {
				http.NotFound(w, r)
				return
			}
			out := gistResp{ID: id, Files: make(map[string]gistFileResp)}
			for name, content := range files {
				out.Files[name] = gistFileResp{Content: content}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodDelete && len(r.URL.Path) > 7 && r.URL.Path[:7] == "/gists/":
			delete(api.gists, r.URL.Path[7:])
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, api
}

type fakeGistAPI struct {
	mu    sync.Mutex
	gists map[string]map[string]string
}

func TestGistResolverRoundTrip(t *testing.T) {
	ts, api := gistServer(t)
	g := NewGist("test-token").WithBaseURL(ts.URL)
	ctx := context.Background()
	payload := bytes.Repeat([]byte("z"), 4096)

	ref := KeyOf(payload)
	if err := g.Publish(ctx, ref, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}
	api.mu.Lock()
	created := len(api.gists) == 1
	api.mu.Unlock()
	if !created {
		t.Fatal("gist not created on api")
	}

	got, err := g.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}

	if err := g.Retire(ctx, ref); err != nil {
		t.Fatalf("retire: %v", err)
	}
	api.mu.Lock()
	left := len(api.gists)
	api.mu.Unlock()
	if left != 0 {
		t.Fatal("gist not deleted on api")
	}
	if _, err := g.Resolve(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after retire, got %v", err)
	}
}

func TestGistResolverUnknownRef(t *testing.T) {
	ts, _ := gistServer(t)
	g := NewGist("test-token").WithBaseURL(ts.URL)
	if _, err := g.Resolve(context.Background(), "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGistResolverUnauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(ts.Close)
	g := NewGist("bad-token").WithBaseURL(ts.URL)
	if err := g.Publish(context.Background(), "ref", []byte("x")); err == nil {
		t.Fatal("unauthorized publish must fail")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
