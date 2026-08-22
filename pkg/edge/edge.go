package edge

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"

	"dark-arts/pkg/crypto"
	"dark-arts/pkg/store"
)

var sidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type Options struct {
	MaxBody   int64
	Logger    *slog.Logger
	CoverHTML string
}

type Server struct {
	store store.Store
	opts  Options
}

func New(st store.Store, opts Options) *Server {
	if opts.MaxBody <= 0 {
		opts.MaxBody = 1 << 20
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.CoverHTML == "" {
		opts.CoverHTML = defaultCover
	}
	return &Server{store: st, opts: opts}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest", s.handleIngest)
	mux.HandleFunc("GET /tasks/{sid}", s.handleTasks)
	mux.HandleFunc("DELETE /tasks/{sid}/{counter}", s.handleDelete)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("/", s.handlePage)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, nginx404)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, s.opts.CoverHTML)
}

const defaultCover = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kraus &amp; Brandt — Structural Engineering</title>
<style>
body{font-family:Georgia,serif;max-width:44rem;margin:4rem auto;padding:0 1.5rem;color:#222}
h1{font-size:2rem;border-bottom:2px solid #c8a64e;padding-bottom:.4rem}
h2{font-size:1.1rem;margin-top:2.2rem}
footer{margin-top:3rem;font-size:.8rem;color:#777}
</style>
</head>
<body>
<h1>Kraus &amp; Brandt</h1>
<p>Structural engineering consultancy. Serving the region since 1998.</p>
<h2>Projects</h2>
<ul>
<li>Meridian Bridge — cable-stayed crossing, load modeling and vibration studies.</li>
<li>Harbor West Mixed-Use — seismic retrofit of a 1970s concrete frame.</li>
<li>Northgate Stadium — long-span roof truss design and fabrication review.</li>
</ul>
<h2>Services</h2>
<ul>
<li>Structural analysis and design (steel, concrete, timber)</li>
<li>Condition assessment and forensic investigation</li>
<li>Construction phase engineering support</li>
</ul>
<footer>&copy; 2026 Kraus &amp; Brandt Engineering. All rights reserved.</footer>
</body>
</html>
`

const nginx404 = `<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.27.4</center>
</body>
</html>
`

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	flow, ok := flowName(r.URL.Query().Get("f"))
	if !ok {
		http.Error(w, "bad flow", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, s.opts.MaxBody+1))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > s.opts.MaxBody {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	env, err := crypto.UnmarshalEnvelope(body)
	if err != nil {
		http.Error(w, "malformed envelope", http.StatusBadRequest)
		return
	}
	if err := validateEnvelope(env); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !sidRe.MatchString(env.SessionID) {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}
	counter := binary.BigEndian.Uint64(env.Nonce[:8])
	key := fmt.Sprintf("%s/%s/%020d", env.SessionID, flow, counter)
	if err := s.store.Put(r.Context(), key, body); err != nil {
		s.opts.Logger.Error("ingest: store put failed", "sid", env.SessionID, "err", err)
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	s.opts.Logger.Info("ingest: stored", "sid", env.SessionID, "flow", flow, "counter", counter)
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if !sidRe.MatchString(sid) {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}
	flow, ok := flowName(r.URL.Query().Get("f"))
	if !ok {
		http.Error(w, "bad flow", http.StatusBadRequest)
		return
	}
	since := uint64(0)
	if q := r.URL.Query().Get("since"); q != "" {
		v, err := strconv.ParseUint(q, 10, 64)
		if err != nil {
			http.Error(w, "bad since", http.StatusBadRequest)
			return
		}
		since = v
	}

	prefix := sid + "/" + flow + "/"
	keys, err := s.store.List(r.Context(), prefix)
	if err != nil {
		s.opts.Logger.Error("tasks: list failed", "sid", sid, "err", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}

	type item struct {
		counter uint64
		raw     json.RawMessage
	}
	var items []item
	for _, k := range keys {
		c, ok := parseCounter(k, prefix)
		if !ok || c < since {
			continue
		}
		b, err := s.store.Get(r.Context(), k)
		if err != nil {
			continue
		}
		if !json.Valid(b) {
			s.opts.Logger.Warn("tasks: skipping corrupt blob", "key", k)
			continue
		}
		items = append(items, item{counter: c, raw: b})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].counter < items[j].counter })

	out := make([]json.RawMessage, 0, len(items))
	for _, it := range items {
		out = append(out, it.raw)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		s.opts.Logger.Error("tasks: encode failed", "sid", sid, "err", err)
	}
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if !sidRe.MatchString(sid) {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}
	flow, ok := flowName(r.URL.Query().Get("f"))
	if !ok {
		http.Error(w, "bad flow", http.StatusBadRequest)
		return
	}
	counter, err := strconv.ParseUint(r.PathValue("counter"), 10, 64)
	if err != nil {
		http.Error(w, "bad counter", http.StatusBadRequest)
		return
	}
	key := fmt.Sprintf("%s/%s/%020d", sid, flow, counter)
	err = s.store.Delete(r.Context(), key)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.opts.Logger.Error("delete: store delete failed", "key", key, "err", err)
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	s.opts.Logger.Info("delete: removed", "key", key)
	w.WriteHeader(http.StatusNoContent)
}

func flowName(v string) (string, bool) {
	if v == "" || v == "beacon" {
		return "beacon", true
	}
	if v == "server" {
		return "server", true
	}
	return "", false
}

func parseCounter(key, prefix string) (uint64, bool) {
	if len(key) <= len(prefix) {
		return 0, false
	}
	v, err := strconv.ParseUint(key[len(prefix):], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func validateEnvelope(env *crypto.MessageEnvelope) error {
	if len(env.Nonce) != 12 {
		return errors.New("bad nonce")
	}
	if len(env.Ciphertext) == 0 {
		return errors.New("empty ciphertext")
	}
	return nil
}
