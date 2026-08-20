package mesh

import (
	"sync"
	"time"
)

type Router struct {
	mu    sync.Mutex
	peers []string
	down  map[string]time.Time
	idx   int
}

func NewRouter(addrs ...string) *Router {
	return &Router{
		peers: append([]string(nil), addrs...),
		down:  make(map[string]time.Time),
	}
}

func (r *Router) Add(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.peers {
		if p == addr {
			return
		}
	}
	r.peers = append(r.peers, addr)
}

func (r *Router) Remove(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, p := range r.peers {
		if p == addr {
			r.peers = append(r.peers[:i], r.peers[i+1:]...)
			delete(r.down, addr)
			return
		}
	}
}

func (r *Router) List() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.peers))
	for _, p := range r.peers {
		out = append(out, p)
	}
	return out
}

func (r *Router) Next() (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.peers) == 0 {
		return "", false
	}
	now := time.Now()
	for i := 0; i < len(r.peers); i++ {
		addr := r.peers[r.idx%len(r.peers)]
		r.idx++
		if until, bad := r.down[addr]; !bad || now.After(until) {
			return addr, true
		}
	}
	return "", false
}

func (r *Router) MarkDown(addr string, forDur time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.down[addr] = time.Now().Add(forDur)
}

func (r *Router) IsDown(addr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	until, bad := r.down[addr]
	return bad && time.Now().Before(until)
}
