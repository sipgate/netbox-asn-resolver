package syncer

import (
	"io"
	"log/slog"
	"testing"

	"github.com/sipgate/netbox-asn-resolver/internal/cache"
	"github.com/sipgate/netbox-asn-resolver/internal/metrics"
	"github.com/sipgate/netbox-asn-resolver/internal/netbox"
)

func newTestSyncer(t *testing.T, format string) *Syncer {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(netbox.NewClient("https://example.com", "token", log), cache.New(), metrics.New(), log, format)
}

func TestRenderTXT(t *testing.T) {
	s := newTestSyncer(t, "%{asn} | %{rir.name} | netbox | %{description}")

	a := netbox.ASN{
		ID:          7,
		ASN:         13335,
		Description: "Cloudflare",
		RIR:         &netbox.NestedRef{ID: 1, Name: "ARIN", Slug: "arin"},
	}

	got := s.renderTXT(a)
	want := "13335 | ARIN | netbox | Cloudflare"
	if got != want {
		t.Errorf("renderTXT = %q; want %q", got, want)
	}
}

func TestRenderTXTCymruFormat(t *testing.T) {
	s := newTestSyncer(t, "%{asn} | %{rir.name} | netbox | %{created} | %{description}")
	a := netbox.ASN{
		ASN:         15169,
		Description: "Google LLC",
		RIR:         &netbox.NestedRef{Name: "ARIN"},
		Created:     "2000-03-30T12:00:00.123456Z",
	}
	got := s.renderTXT(a)
	want := "15169 | ARIN | netbox | 2000-03-30 | Google LLC"
	if got != want {
		t.Errorf("renderTXT = %q; want %q", got, want)
	}
}

func TestDateOnly(t *testing.T) {
	cases := map[string]string{
		"2023-01-15T10:30:00.123456Z": "2023-01-15",
		"2023-01-15T10:30:00Z":        "2023-01-15",
		"2023-01-15":                  "2023-01-15", // already date-only
		"":                            "",
	}
	for in, want := range cases {
		if got := dateOnly(in); got != want {
			t.Errorf("dateOnly(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestRenderTXTNilNested(t *testing.T) {
	s := newTestSyncer(t, "%{asn}|%{rir.name}|%{tenant.slug}")
	got := s.renderTXT(netbox.ASN{ASN: 64500}) // no rir, no tenant
	want := "64500||"
	if got != want {
		t.Errorf("renderTXT with nil nested = %q; want %q", got, want)
	}
}

func TestRenderTXTUnknownPlaceholder(t *testing.T) {
	s := newTestSyncer(t, "x=%{nope}=y")
	got := s.renderTXT(netbox.ASN{ASN: 1})
	if got != "x==y" {
		t.Errorf("unknown placeholder rendered %q; want %q", got, "x==y")
	}
}

func TestBuildCacheDedup(t *testing.T) {
	s := newTestSyncer(t, "%{asn}|%{description}")
	m := s.buildCache([]netbox.ASN{
		{ASN: 100, Description: "first"},
		{ASN: 200, Description: "second"},
		{ASN: 100, Description: "duplicate"},
	})

	if len(m) != 2 {
		t.Fatalf("expected 2 unique entries, got %d", len(m))
	}
	if m["100"] != "100|first" {
		t.Errorf("duplicate ASN should keep first entry, got %q", m["100"])
	}
	if m["200"] != "200|second" {
		t.Errorf("unexpected entry for 200: %q", m["200"])
	}
}

func TestCompileTemplate(t *testing.T) {
	segs := compileTemplate("a%{asn}b%{rir.name}")
	// literal "a", key "asn", literal "b", key "rir.name"
	if len(segs) != 4 {
		t.Fatalf("expected 4 segments, got %d: %+v", len(segs), segs)
	}
	if segs[0].literal != "a" || segs[0].key != "" {
		t.Errorf("seg0 = %+v", segs[0])
	}
	if segs[1].key != "asn" {
		t.Errorf("seg1 = %+v", segs[1])
	}
	if segs[2].literal != "b" {
		t.Errorf("seg2 = %+v", segs[2])
	}
	if segs[3].key != "rir.name" {
		t.Errorf("seg3 = %+v", segs[3])
	}
}

func TestAsnField(t *testing.T) {
	a := netbox.ASN{ID: 9, ASN: 13335, Description: "d"}
	a.Tenant = &netbox.NestedRef{ID: 3, Name: "Acme", Slug: "acme"}

	cases := map[string]string{
		"asn":         "13335",
		"id":          "9",
		"description": "d",
		"tenant.id":   "3",
		"tenant.name": "Acme",
		"tenant.slug": "acme",
		"rir.name":    "", // nil RIR
		"bogus":       "",
	}
	for key, want := range cases {
		if got := asnField(a, key); got != want {
			t.Errorf("asnField(%q) = %q; want %q", key, got, want)
		}
	}
}
