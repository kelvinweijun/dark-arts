package mimic

import (
	"math/rand"
	"net/http"
	"sync"
)

var pools = map[string][]string{
	"windows-chrome": {
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	},
	"windows-edge": {
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
	},
	"windows-firefox": {
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	},
	"macos-safari": {
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	},
	"macos-chrome": {
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	},
	"linux-chrome": {
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	},
	"linux-firefox": {
		"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	},
}

func Pool(platform string) []string {
	if p, ok := pools[platform]; ok {
		return p
	}
	return pools["windows-chrome"]
}

func Platforms() []string {
	out := make([]string, 0, len(pools))
	for k := range pools {
		out = append(out, k)
	}
	return out
}

type Rotator struct {
	mu   sync.Mutex
	pool []string
}

func NewRotator(platform string) *Rotator {
	return &Rotator{pool: Pool(platform)}
}

func (r *Rotator) Add(ua string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.pool {
		if p == ua {
			return
		}
	}
	r.pool = append(r.pool, ua)
}

func (r *Rotator) Next() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pool) == 0 {
		return ""
	}
	return r.pool[rand.Intn(len(r.pool))]
}

func BrowserHeaders() http.Header {
	h := http.Header{}
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Accept-Encoding", "gzip, deflate, br")
	h.Set("Cache-Control", "max-age=0")
	h.Set("Connection", "keep-alive")
	h.Set("Upgrade-Insecure-Requests", "1")
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Site", "none")
	h.Set("Sec-Fetch-User", "?1")
	return h
}
