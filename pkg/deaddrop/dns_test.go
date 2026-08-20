package deaddrop

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	testKeyName = "darkarts-tsig."
	testSecret  = "22jBF/BOePhdr9ocfm1Nb9VSUQFp1jn5KbxdO4bpneE="
)

type fakeDNSStore struct {
	mu   sync.Mutex
	txts map[string][]string
}

func (s *fakeDNSStore) handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if r.IsTsig() != nil && w.TsigStatus() != nil {
		m.SetRcode(r, dns.RcodeNotAuth)
		w.WriteMsg(m)
		return
	}
	if r.Opcode == dns.OpcodeUpdate {
		s.mu.Lock()
		for _, rr := range r.Ns {
			h := rr.Header()
			if h.Class == dns.ClassANY && h.Ttl == 0 {
				delete(s.txts, h.Name)
				continue
			}
			if txt, ok := rr.(*dns.TXT); ok {
				s.txts[h.Name] = txt.Txt
			}
		}
		s.mu.Unlock()
		w.WriteMsg(m)
		return
	}
	qname := r.Question[0].Name
	s.mu.Lock()
	txts, ok := s.txts[qname]
	s.mu.Unlock()
	if !ok {
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
		return
	}
	m.Answer = append(m.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: txtTTL},
		Txt: txts,
	})
	w.WriteMsg(m)
}

func startFakeDNS(t *testing.T) string {
	t.Helper()
	store := &fakeDNSStore{txts: make(map[string][]string)}
	srv := &dns.Server{
		Addr:       "127.0.0.1:0",
		Net:        "udp",
		Handler:    dns.HandlerFunc(store.handler),
		TsigSecret: map[string]string{testKeyName: testSecret},
		UDPSize:    65535,
		MsgAcceptFunc: func(dh dns.Header) dns.MsgAcceptAction {
			return dns.MsgAccept
		},
	}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() {
		_ = srv.ListenAndServe()
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("fake dns server did not start")
	}
	t.Cleanup(func() { _ = srv.ShutdownContext(context.Background()) })
	return srv.PacketConn.LocalAddr().String()
}

func newTestDNS(addr string) *DNS {
	return NewDNS(addr, "darkarts.lab.", testKeyName, testSecret)
}

func TestDNSResolverRoundTrip(t *testing.T) {
	addr := startFakeDNS(t)
	d := newTestDNS(addr)
	ctx := context.Background()
	payload := bytes.Repeat([]byte("payload-"), 1000)

	ref := KeyOf(payload)
	if err := d.Publish(ctx, ref, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, err := d.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %d vs %d bytes", len(got), len(payload))
	}

	if err := d.Retire(ctx, ref); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := d.Resolve(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after retire, got %v", err)
	}
}

func TestDNSResolverMissing(t *testing.T) {
	addr := startFakeDNS(t)
	d := newTestDNS(addr)
	if _, err := d.Resolve(context.Background(), "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDNSResolverLargePayloadChunking(t *testing.T) {
	addr := startFakeDNS(t)
	d := newTestDNS(addr)
	ctx := context.Background()
	payload := bytes.Repeat([]byte("x"), 8*1024)

	ref := KeyOf(payload)
	if err := d.Publish(ctx, ref, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, err := d.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestDNSResolverWrongTsigRejected(t *testing.T) {
	addr := startFakeDNS(t)
	d := NewDNS(addr, "darkarts.lab.", testKeyName, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err := d.Publish(context.Background(), "ref", []byte("x")); err == nil {
		t.Fatal("publish with wrong tsig secret must fail")
	}
}

func TestDNSResolverUnavailable(t *testing.T) {
	d := NewDNS("127.0.0.1:1", "darkarts.lab.", testKeyName, testSecret).WithTimeout(300 * time.Millisecond)
	if _, err := d.Resolve(context.Background(), "ref"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestChunkString(t *testing.T) {
	c := chunkString("abcdef", 3)
	if len(c) != 2 || c[0] != "abc" || c[1] != "def" {
		t.Fatalf("chunking failed: %v", c)
	}
	if got := chunkString("", 3); len(got) != 0 {
		t.Fatalf("empty must chunk to zero: %v", got)
	}
}
