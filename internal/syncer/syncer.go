// Package syncer keeps the in-memory cache populated from Netbox. It performs a
// blocking initial sync at startup and then refreshes periodically in the
// background, preserving the last-known-good cache on transient failures.
package syncer

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rbott/netbox-asn-resolver/internal/cache"
	"github.com/rbott/netbox-asn-resolver/internal/metrics"
	"github.com/rbott/netbox-asn-resolver/internal/netbox"
)

// Syncer wires the Netbox client, the cache, and metrics together.
type Syncer struct {
	client  *netbox.Client
	cache   *cache.Cache
	metrics *metrics.Metrics
	log     *slog.Logger

	txtFormat string        // NETBOX_TXT_FORMAT template (kept for logging)
	tmpl      []tmplSegment // compiled txtFormat
	timeout   time.Duration // per-sync API timeout
}

// New constructs a Syncer. txtFormat is the configurable TXT template; its
// %{...} placeholders are compiled once here and expanded per ASN during sync.
func New(client *netbox.Client, c *cache.Cache, m *metrics.Metrics, log *slog.Logger, txtFormat string) *Syncer {
	tmpl := compileTemplate(txtFormat)

	// Warn about placeholders that don't map to a known ASN field — they will
	// render as empty strings, so surfacing them early helps spot typos.
	for _, seg := range tmpl {
		if seg.key != "" && !knownPlaceholders[seg.key] {
			log.Warn("unknown placeholder in NETBOX_TXT_FORMAT; will render empty",
				"placeholder", "%{"+seg.key+"}")
		}
	}

	return &Syncer{
		client:    client,
		cache:     c,
		metrics:   m,
		log:       log,
		txtFormat: txtFormat,
		tmpl:      tmpl,
		timeout:   30 * time.Second,
	}
}

// InitialSync performs the mandatory first sync. The caller MUST treat a
// returned error as fatal (log.Fatal / exit) per the spec: the DNS server must
// not start serving without an initial cache.
func (s *Syncer) InitialSync(ctx context.Context) error {
	if err := s.syncOnce(ctx); err != nil {
		return fmt.Errorf("initial sync failed: %w", err)
	}
	return nil
}

// Run blocks running periodic syncs on the configured interval until ctx is
// cancelled. Errors during runtime are logged and counted but never clear the
// existing cache.
func (s *Syncer) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.log.Info("netbox sync loop started", "interval", interval.String())
	for {
		select {
		case <-ctx.Done():
			s.log.Info("netbox sync loop stopped")
			return
		case <-ticker.C:
			if err := s.syncOnce(ctx); err != nil {
				// Keep last-known-good state; just log and count.
				s.log.Error("netbox sync failed, keeping previous cache", "error", err)
			}
		}
	}
}

// syncOnce fetches ASNs from Netbox, builds the new cache map, and swaps it in.
// It updates the success/error counters and the cached-ASNs gauge.
func (s *Syncer) syncOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	asns, err := s.client.FetchASNs(ctx)
	if err != nil {
		s.metrics.NetboxSyncErrors.Inc()
		return err
	}

	newMap := s.buildCache(asns)

	s.cache.Store(newMap)
	s.metrics.CachedASNs.Set(float64(len(newMap)))
	s.metrics.NetboxSyncSuccess.Inc()
	s.log.Info("netbox sync complete", "asns", len(newMap))
	return nil
}

// buildCache converts the fetched Netbox ASN objects into the map[string]string
// stored in the cache. The key is the numeric ASN as a decimal string (e.g.
// "13335"), which is what the DNS handler looks up after stripping the zone and
// an optional "AS" prefix. The value is the expanded NETBOX_TXT_FORMAT template.
func (s *Syncer) buildCache(asns []netbox.ASN) map[string]string {
	m := make(map[string]string, len(asns))
	for _, a := range asns {
		key := strconv.FormatInt(a.ASN, 10)
		if existing, dup := m[key]; dup {
			s.log.Warn("duplicate ASN from Netbox; keeping first entry",
				"asn", key, "kept", existing)
			continue
		}
		m[key] = s.renderTXT(a)
	}
	return m
}

// renderTXT expands the compiled template for a single ASN.
func (s *Syncer) renderTXT(a netbox.ASN) string {
	var b strings.Builder
	for _, seg := range s.tmpl {
		if seg.key == "" {
			b.WriteString(seg.literal)
			continue
		}
		b.WriteString(asnField(a, seg.key))
	}
	return b.String()
}

// tmplSegment is either a run of literal text (key == "") or a placeholder key.
type tmplSegment struct {
	literal string
	key     string
}

var placeholderRe = regexp.MustCompile(`%\{([^}]+)\}`)

// compileTemplate splits a format string into literal and placeholder segments
// so the template is parsed once rather than per ASN.
func compileTemplate(format string) []tmplSegment {
	var segs []tmplSegment
	last := 0
	for _, m := range placeholderRe.FindAllStringSubmatchIndex(format, -1) {
		if m[0] > last {
			segs = append(segs, tmplSegment{literal: format[last:m[0]]})
		}
		segs = append(segs, tmplSegment{key: format[m[2]:m[3]]})
		last = m[1]
	}
	if last < len(format) {
		segs = append(segs, tmplSegment{literal: format[last:]})
	}
	return segs
}

// knownPlaceholders is the set of supported template keys, used only for the
// startup typo warning. asnField is the source of truth for resolution.
var knownPlaceholders = map[string]bool{
	"asn":          true,
	"id":           true,
	"description":  true,
	"created":      true,
	"last_updated": true,
	"rir.id":       true,
	"rir.name":     true,
	"rir.slug":     true,
	"tenant.id":    true,
	"tenant.name":  true,
	"tenant.slug":  true,
}

// dateOnly trims a Netbox ISO-8601 timestamp ("2023-01-15T10:30:00.123456Z")
// to its date component ("2023-01-15") so it matches the Team Cymru date
// format. Empty values and values without a time component pass through
// unchanged.
func dateOnly(ts string) string {
	if i := strings.IndexByte(ts, 'T'); i > 0 {
		return ts[:i]
	}
	return ts
}

// asnField resolves a single placeholder key against an ASN object. Unknown
// keys and absent nested objects (nil rir/tenant) resolve to the empty string.
func asnField(a netbox.ASN, key string) string {
	switch key {
	case "asn":
		return strconv.FormatInt(a.ASN, 10)
	case "id":
		return strconv.Itoa(a.ID)
	case "description":
		return a.Description
	case "created":
		return dateOnly(a.Created)
	case "last_updated":
		return dateOnly(a.LastUpdated)
	case "rir.id":
		if a.RIR != nil {
			return strconv.Itoa(a.RIR.ID)
		}
	case "rir.name":
		if a.RIR != nil {
			return a.RIR.Name
		}
	case "rir.slug":
		if a.RIR != nil {
			return a.RIR.Slug
		}
	case "tenant.id":
		if a.Tenant != nil {
			return strconv.Itoa(a.Tenant.ID)
		}
	case "tenant.name":
		if a.Tenant != nil {
			return a.Tenant.Name
		}
	case "tenant.slug":
		if a.Tenant != nil {
			return a.Tenant.Slug
		}
	}
	return ""
}
