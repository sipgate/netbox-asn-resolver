// Package dnsserver implements the DNS front-end: it listens on UDP and TCP,
// parses ASN TXT queries scoped to the configured zone, and dispatches them
// through the resolution pipeline.
package dnsserver

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/rbott/netbox-asn-resolver/internal/cache"
	"github.com/rbott/netbox-asn-resolver/internal/metrics"
)

// RFC 6996 private-use ASN ranges. ASNs in these ranges must never be
// forwarded to an upstream resolver.
const (
	privateASN16Lo = 64512
	privateASN16Hi = 65534
	privateASN32Lo = 4200000000
	privateASN32Hi = 4294967294
)

// defaultUpstreamZone is the well-known Team Cymru zone queried for public
// ASNs not present in Netbox.
const defaultUpstreamZone = "asn.cymru.com."

// Server runs the UDP and TCP DNS listeners.
type Server struct {
	cfg      Config
	cache    *cache.Cache
	metrics  *metrics.Metrics
	log      *slog.Logger
	upstream *dns.Client // client used for the public-ASN fallback

	udp *dns.Server
	tcp *dns.Server
}

// Config holds the DNS-specific settings the server needs.
type Config struct {
	ListenAddr   string // e.g. ":53"
	Zone         string // fully-qualified, trailing dot, lower-case
	UpstreamDNS  string // resolver address for the public fallback, e.g. "8.8.8.8:53"
	UpstreamZone string // zone queried upstream; defaults to "asn.cymru.com."
	TTL          uint32 // TTL for cache/Netbox-sourced answers (spec: 300)
}

// New constructs a DNS server bound to the given dependencies.
func New(cfg Config, c *cache.Cache, m *metrics.Metrics, log *slog.Logger) *Server {
	if cfg.TTL == 0 {
		cfg.TTL = 300
	}
	if cfg.UpstreamZone == "" {
		cfg.UpstreamZone = defaultUpstreamZone
	}
	cfg.UpstreamZone = dns.Fqdn(strings.ToLower(cfg.UpstreamZone))
	return &Server{
		cfg:      cfg,
		cache:    c,
		metrics:  m,
		log:      log,
		upstream: &dns.Client{Timeout: 5 * time.Second},
	}
}

// ListenAndServe starts the UDP and TCP listeners and blocks until one of them
// returns an error (or the server is shut down). The first non-nil error is
// returned via the supplied channel-free errgroup-style helper below.
func (s *Server) ListenAndServe() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(s.cfg.Zone, s.handle)

	s.udp = &dns.Server{Addr: s.cfg.ListenAddr, Net: "udp", Handler: mux}
	s.tcp = &dns.Server{Addr: s.cfg.ListenAddr, Net: "tcp", Handler: mux}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	record := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		s.log.Info("dns listener starting", "net", "udp", "addr", s.cfg.ListenAddr, "zone", s.cfg.Zone)
		record(s.udp.ListenAndServe())
	}()
	go func() {
		defer wg.Done()
		s.log.Info("dns listener starting", "net", "tcp", "addr", s.cfg.ListenAddr, "zone", s.cfg.Zone)
		record(s.tcp.ListenAndServe())
	}()

	wg.Wait()
	return firstErr
}

// Shutdown gracefully stops both listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	var firstErr error
	if s.udp != nil {
		if err := s.udp.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.tcp != nil {
		if err := s.tcp.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// handle is the entry point for every query in the configured zone. It runs the
// resolution pipeline, writes the reply, and records the appropriate Prometheus
// status:
//
//	Step A — Cache hit:   look up the ASN in s.cache; on hit, answer with a TXT
//	                      record (TTL s.cfg.TTL) and count metrics.StatusHit.
//	Step B — Private ASN: if missing, reject private ASNs (RFC 6996) with
//	                      NXDOMAIN and count metrics.StatusMissPrivate. The
//	                      query is NOT forwarded upstream.
//	Step C — Upstream:    for public ASNs, query s.cfg.UpstreamDNS for
//	                      "AS<ASN>.<UpstreamZone>" and forward the TXT answer;
//	                      count metrics.StatusUpstreamHit / StatusUpstreamMiss.
func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Only TXT questions are meaningful here; everything else gets an empty
	// NOERROR.
	if len(r.Question) != 1 || r.Question[0].Qtype != dns.TypeTXT {
		if len(r.Question) == 1 {
			s.log.Debug("ignoring non-TXT query",
				"name", r.Question[0].Name,
				"type", dns.TypeToString[r.Question[0].Qtype],
				"client", w.RemoteAddr().String())
		}
		_ = w.WriteMsg(m)
		return
	}

	qname := r.Question[0].Name
	s.log.Debug("dns query received", "name", qname, "client", w.RemoteAddr().String())

	asn, value, ok := s.parseASN(qname)
	if !ok {
		// Malformed name within our zone -> NXDOMAIN.
		s.log.Debug("unparseable ASN query name, returning NXDOMAIN", "name", qname)
		m.Rcode = dns.RcodeNameError
		s.metrics.DNSRequests.WithLabelValues(metrics.StatusError).Inc()
		_ = w.WriteMsg(m)
		return
	}

	// Step A — cache hit.
	if asnData, ok := s.cache.Get(asn); ok {
		s.log.Debug("cache hit", "asn", asn, "value", asnData)
		m.Rcode = dns.RcodeSuccess
		m.Answer = []dns.RR{newTXT(qname, s.cfg.TTL, asnData)}
		_ = w.WriteMsg(m)
		s.metrics.DNSRequests.WithLabelValues(metrics.StatusHit).Inc()
		return
	}

	// Step B — private ASN: never forwarded upstream.
	if isPrivateASN(value) {
		s.log.Debug("private ASN not in cache, returning NXDOMAIN without upstream", "asn", asn)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		s.metrics.DNSRequests.WithLabelValues(metrics.StatusMissPrivate).Inc()
		return
	}

	s.log.Debug("cache miss for public ASN, falling back to upstream", "asn", asn)

	// Step C — public ASN: fall back to the upstream resolver.
	s.resolveUpstream(w, m, qname, asn)
}

// resolveUpstream queries the configured upstream resolver for the public ASN
// and forwards any TXT answer under the original query name.
func (s *Server) resolveUpstream(w dns.ResponseWriter, m *dns.Msg, qname, asn string) {
	upstreamName := dns.Fqdn("AS" + asn + "." + s.cfg.UpstreamZone)
	q := new(dns.Msg)
	q.SetQuestion(upstreamName, dns.TypeTXT)
	q.RecursionDesired = true

	s.log.Debug("querying upstream", "asn", asn, "query", upstreamName, "upstream", s.cfg.UpstreamDNS)
	resp, rtt, err := s.upstream.Exchange(q, s.cfg.UpstreamDNS)
	if err != nil {
		s.log.Warn("upstream query failed", "asn", asn, "upstream", s.cfg.UpstreamDNS, "error", err)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		s.metrics.DNSRequests.WithLabelValues(metrics.StatusError).Inc()
		return
	}

	var answers []dns.RR
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		// Re-home the answer under the name the client actually asked for.
		answers = append(answers, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    txt.Hdr.Ttl,
			},
			Txt: txt.Txt,
		})
	}

	if len(answers) == 0 {
		s.log.Debug("upstream returned no TXT answer", "asn", asn, "rcode", dns.RcodeToString[resp.Rcode], "rtt", rtt.String())
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		s.metrics.DNSRequests.WithLabelValues(metrics.StatusUpstreamMiss).Inc()
		return
	}

	s.log.Debug("upstream hit", "asn", asn, "answers", len(answers), "rtt", rtt.String())
	m.Rcode = dns.RcodeSuccess
	m.Answer = answers
	_ = w.WriteMsg(m)
	s.metrics.DNSRequests.WithLabelValues(metrics.StatusUpstreamHit).Inc()
}

// newTXT builds a single TXT answer record for the given name/TTL/value.
func newTXT(name string, ttl uint32, value string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Txt: []string{value},
	}
}

// isPrivateASN reports whether the ASN falls in an RFC 6996 private-use range.
func isPrivateASN(asn uint64) bool {
	return (asn >= privateASN16Lo && asn <= privateASN16Hi) ||
		(asn >= privateASN32Lo && asn <= privateASN32Hi)
}

// parseASN extracts the ASN from a query name within the configured zone. It
// accepts both "AS13335.<zone>" and "13335.<zone>" (case-insensitive) but
// rejects names outside the zone, the zone apex, and names with extra labels
// (e.g. "foo.13335.<zone>"). It returns the canonical decimal cache key, the
// numeric value (for the private-range check), and whether parsing succeeded.
func (s *Server) parseASN(qname string) (string, uint64, bool) {
	name := strings.ToLower(qname)

	// Must be inside our zone.
	if !strings.HasSuffix(name, s.cfg.Zone) {
		return "", 0, false
	}
	label := strings.TrimSuffix(name, s.cfg.Zone)
	label = strings.TrimSuffix(label, ".")

	// Reject the apex (no ASN label) and any name with extra labels.
	if label == "" || strings.Contains(label, ".") {
		return "", 0, false
	}

	label = strings.TrimPrefix(label, "as")
	value, err := strconv.ParseUint(label, 10, 32)
	if err != nil {
		return "", 0, false
	}

	// Canonicalise the key (drops a leading "AS" and any leading zeros) so it
	// matches the decimal keys the syncer stores.
	return strconv.FormatUint(value, 10), value, true
}
