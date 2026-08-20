package deaddrop

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	txtTTL       = 60
	txtChunkSize = 255
)

type DNS struct {
	server  string
	zone    string
	keyName string
	secret  string
	client  *dns.Client
}

func NewDNS(server, zone, keyName, secret string) *DNS {
	return &DNS{
		server:  server,
		zone:    dns.Fqdn(zone),
		keyName: dns.Fqdn(keyName),
		secret:  secret,
		client:  &dns.Client{Timeout: 5 * time.Second, UDPSize: 65535},
	}
}

func (d *DNS) WithTimeout(t time.Duration) *DNS {
	d.client.Timeout = t
	return d
}

func (d *DNS) roundtrip(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	resp, _, err := d.client.ExchangeContext(ctx, m, d.server)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		m.SetTsig(d.keyName, dns.HmacSHA256, 300, time.Now().Unix())
		tc := &dns.Client{Timeout: d.client.Timeout, Net: "tcp", TsigSecret: d.client.TsigSecret}
		resp, _, err = tc.ExchangeContext(ctx, m, d.server)
		return resp, err
	}
	return resp, nil
}

func (d *DNS) txtName(ref string) string {
	return "_dd." + ref + "." + d.zone
}

func chunkString(s string, size int) []string {
	var chunks []string
	for len(s) > 0 {
		n := size
		if len(s) < n {
			n = len(s)
		}
		chunks = append(chunks, s[:n])
		s = s[n:]
	}
	return chunks
}

func (d *DNS) Publish(ctx context.Context, ref string, payload []byte) error {
	b64 := base64.StdEncoding.EncodeToString(payload)
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   d.txtName(ref),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    txtTTL,
		},
		Txt: chunkString(b64, txtChunkSize),
	}
	m := new(dns.Msg)
	m.SetUpdate(d.zone)
	m.Insert([]dns.RR{rr})
	return d.exchange(ctx, m)
}

func (d *DNS) Resolve(ctx context.Context, ref string) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(d.txtName(ref), dns.TypeTXT)
	m.SetEdns0(65535, false)
	resp, err := d.roundtrip(ctx, m)
	if err != nil {
		return nil, ErrUnavailable
	}
	switch resp.Rcode {
	case dns.RcodeNameError:
		return nil, ErrNotFound
	case dns.RcodeSuccess:
	default:
		return nil, ErrUnavailable
	}
	var parts []string
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			parts = append(parts, txt.Txt...)
		}
	}
	if len(parts) == 0 {
		return nil, ErrNotFound
	}
	return base64.StdEncoding.DecodeString(strings.Join(parts, ""))
}

func (d *DNS) Retire(ctx context.Context, ref string) error {
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   d.txtName(ref),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassANY,
			Ttl:    0,
		},
	}
	m := new(dns.Msg)
	m.SetUpdate(d.zone)
	m.RemoveRRset([]dns.RR{rr})
	return d.exchange(ctx, m)
}

func (d *DNS) exchange(ctx context.Context, m *dns.Msg) error {
	m.SetTsig(d.keyName, dns.HmacSHA256, 300, time.Now().Unix())
	d.client.TsigSecret = map[string]string{d.keyName: d.secret}
	resp, err := d.roundtrip(ctx, m)
	if err != nil {
		return ErrUnavailable
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("deaddrop: dns rcode %d", resp.Rcode)
	}
	return nil
}
