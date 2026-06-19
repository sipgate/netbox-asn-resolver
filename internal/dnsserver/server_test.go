package dnsserver

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/rbott/netbox-asn-resolver/internal/cache"
	"github.com/rbott/netbox-asn-resolver/internal/metrics"
)

// counterValue reads the current value of a Prometheus counter without pulling
// in the testutil package (which has extra transitive dependencies).
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

const testZone = "asn.example.com."

// fakeRW captures the message a handler writes without touching the network.
type fakeRW struct{ msg *dns.Msg }

func (f *fakeRW) LocalAddr() net.Addr  { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (f *fakeRW) RemoteAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242} }
func (f *fakeRW) WriteMsg(m *dns.Msg) error    { f.msg = m; return nil }
func (f *fakeRW) Write([]byte) (int, error)    { return 0, nil }
func (f *fakeRW) Close() error                 { return nil }
func (f *fakeRW) TsigStatus() error            { return nil }
func (f *fakeRW) TsigTimersOnly(bool)          {}
func (f *fakeRW) Hijack()                       {}

func newTestServer(t *testing.T, c *cache.Cache, m *metrics.Metrics, cfg Config) *Server {
	t.Helper()
	if cfg.Zone == "" {
		cfg.Zone = testZone
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, c, m, log)
}

func txtQuery(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	return q
}

func TestParseASN(t *testing.T) {
	s := newTestServer(t, cache.New(), metrics.New(), Config{Zone: testZone})

	cases := []struct {
		name    string
		qname   string
		wantKey string
		wantVal uint64
		wantOK  bool
	}{
		{"plain numeric", "13335.asn.example.com.", "13335", 13335, true},
		{"AS prefix", "AS13335.asn.example.com.", "13335", 13335, true},
		{"lowercase as prefix", "as13335.asn.example.com.", "13335", 13335, true},
		{"leading zeros canonicalised", "AS000013335.asn.example.com.", "13335", 13335, true},
		{"32-bit asn", "AS4200000000.asn.example.com.", "4200000000", 4200000000, true},
		{"apex rejected", "asn.example.com.", "", 0, false},
		{"extra label rejected", "foo.13335.asn.example.com.", "", 0, false},
		{"non-numeric rejected", "abc.asn.example.com.", "", 0, false},
		{"as without digits rejected", "AS.asn.example.com.", "", 0, false},
		{"out of zone rejected", "13335.other.example.com.", "", 0, false},
		{"overflow rejected", "AS99999999999.asn.example.com.", "", 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, val, ok := s.parseASN(tc.qname)
			if ok != tc.wantOK || key != tc.wantKey || val != tc.wantVal {
				t.Fatalf("parseASN(%q) = (%q, %d, %v); want (%q, %d, %v)",
					tc.qname, key, val, ok, tc.wantKey, tc.wantVal, tc.wantOK)
			}
		})
	}
}

func TestIsPrivateASN(t *testing.T) {
	cases := []struct {
		asn  uint64
		want bool
	}{
		{13335, false},
		{64511, false},
		{64512, true},
		{65000, true},
		{65534, true},
		{65535, false}, // reserved, not RFC 6996 private
		{4199999999, false},
		{4200000000, true},
		{4294967294, true},
		{4294967295, false},
	}
	for _, tc := range cases {
		if got := isPrivateASN(tc.asn); got != tc.want {
			t.Errorf("isPrivateASN(%d) = %v; want %v", tc.asn, got, tc.want)
		}
	}
}

func TestHandleCacheHit(t *testing.T) {
	c := cache.New()
	c.Store(map[string]string{"13335": "13335 | ARIN | netbox | Cloudflare"})
	m := metrics.New()
	s := newTestServer(t, c, m, Config{Zone: testZone, TTL: 300})

	rw := &fakeRW{}
	s.handle(rw, txtQuery("AS13335.asn.example.com"))

	if rw.msg == nil || rw.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %+v", rw.msg)
	}
	if len(rw.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(rw.msg.Answer))
	}
	txt := rw.msg.Answer[0].(*dns.TXT)
	if txt.Txt[0] != "13335 | ARIN | netbox | Cloudflare" {
		t.Errorf("unexpected TXT %q", txt.Txt[0])
	}
	if txt.Hdr.Ttl != 300 {
		t.Errorf("expected TTL 300, got %d", txt.Hdr.Ttl)
	}
	if got := counterValue(t, m.DNSRequests.WithLabelValues(metrics.StatusHit)); got != 1 {
		t.Errorf("StatusHit = %v; want 1", got)
	}
}

func TestHandlePrivateASN(t *testing.T) {
	m := metrics.New()
	// Point upstream at an unroutable address: if Step B leaked into Step C the
	// test would hang/fail rather than silently pass.
	s := newTestServer(t, cache.New(), m, Config{Zone: testZone, UpstreamDNS: "192.0.2.1:53"})

	rw := &fakeRW{}
	s.handle(rw, txtQuery("AS64512.asn.example.com"))

	if rw.msg == nil || rw.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %+v", rw.msg)
	}
	if len(rw.msg.Answer) != 0 {
		t.Errorf("expected no answers, got %d", len(rw.msg.Answer))
	}
	if got := counterValue(t, m.DNSRequests.WithLabelValues(metrics.StatusMissPrivate)); got != 1 {
		t.Errorf("StatusMissPrivate = %v; want 1", got)
	}
}

func TestHandleMalformed(t *testing.T) {
	m := metrics.New()
	s := newTestServer(t, cache.New(), m, Config{Zone: testZone})

	rw := &fakeRW{}
	s.handle(rw, txtQuery("foo.bar.asn.example.com"))

	if rw.msg == nil || rw.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %+v", rw.msg)
	}
	if got := counterValue(t, m.DNSRequests.WithLabelValues(metrics.StatusError)); got != 1 {
		t.Errorf("StatusError = %v; want 1", got)
	}
}

func TestHandleNonTXT(t *testing.T) {
	s := newTestServer(t, cache.New(), metrics.New(), Config{Zone: testZone})
	q := new(dns.Msg)
	q.SetQuestion("AS13335.asn.example.com.", dns.TypeA)

	rw := &fakeRW{}
	s.handle(rw, q)
	if rw.msg == nil || rw.msg.Rcode != dns.RcodeSuccess || len(rw.msg.Answer) != 0 {
		t.Fatalf("expected empty NOERROR, got %+v", rw.msg)
	}
}

// startUpstream spins up a real DNS server on an ephemeral loopback UDP port so
// the upstream-fallback path is exercised end-to-end through dns.Client.
func startUpstream(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream server did not start")
	}
	return pc.LocalAddr().String()
}

func TestHandleUpstreamHit(t *testing.T) {
	upstreamAddr := startUpstream(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		if r.Question[0].Name == "AS15169.asn.cymru.com." {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 100},
				Txt: []string{"15169 | US | arin | GOOGLE"},
			})
		}
		_ = w.WriteMsg(resp)
	})

	m := metrics.New()
	s := newTestServer(t, cache.New(), m, Config{Zone: testZone, UpstreamDNS: upstreamAddr})

	rw := &fakeRW{}
	s.handle(rw, txtQuery("AS15169.asn.example.com"))

	if rw.msg == nil || rw.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %+v", rw.msg)
	}
	if len(rw.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(rw.msg.Answer))
	}
	txt := rw.msg.Answer[0].(*dns.TXT)
	if txt.Txt[0] != "15169 | US | arin | GOOGLE" {
		t.Errorf("unexpected TXT %q", txt.Txt[0])
	}
	// Answer must be re-homed under the original query name.
	if txt.Hdr.Name != "as15169.asn.example.com." && txt.Hdr.Name != "AS15169.asn.example.com." {
		t.Errorf("answer name not re-homed: %q", txt.Hdr.Name)
	}
	if got := counterValue(t, m.DNSRequests.WithLabelValues(metrics.StatusUpstreamHit)); got != 1 {
		t.Errorf("StatusUpstreamHit = %v; want 1", got)
	}
}

func TestHandleUpstreamMiss(t *testing.T) {
	upstreamAddr := startUpstream(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeNameError // no such ASN upstream
		_ = w.WriteMsg(resp)
	})

	m := metrics.New()
	s := newTestServer(t, cache.New(), m, Config{Zone: testZone, UpstreamDNS: upstreamAddr})

	rw := &fakeRW{}
	s.handle(rw, txtQuery("AS65999.asn.example.com")) // public, not in cache

	if rw.msg == nil || rw.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %+v", rw.msg)
	}
	if len(rw.msg.Answer) != 0 {
		t.Errorf("expected no answers, got %d", len(rw.msg.Answer))
	}
	if got := counterValue(t, m.DNSRequests.WithLabelValues(metrics.StatusUpstreamMiss)); got != 1 {
		t.Errorf("StatusUpstreamMiss = %v; want 1", got)
	}
}

func TestHandleUpstreamError(t *testing.T) {
	m := metrics.New()
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed unroutable.
	s := newTestServer(t, cache.New(), m, Config{Zone: testZone, UpstreamDNS: "192.0.2.1:53"})
	s.upstream.Timeout = 200 * time.Millisecond

	rw := &fakeRW{}
	s.handle(rw, txtQuery("AS65999.asn.example.com"))

	if rw.msg == nil || rw.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got %+v", rw.msg)
	}
	if got := counterValue(t, m.DNSRequests.WithLabelValues(metrics.StatusError)); got != 1 {
		t.Errorf("StatusError = %v; want 1", got)
	}
}
