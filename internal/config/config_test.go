package config

import (
	"testing"
	"time"
)

func TestNormalizeZone(t *testing.T) {
	cases := map[string]string{
		"asn.cymru.com":   "asn.cymru.com.",
		"asn.cymru.com.":  "asn.cymru.com.",
		"  ASN.Cymru.COM": "asn.cymru.com.",
		"":                "",
	}
	for in, want := range cases {
		if got := normalizeZone(in); got != want {
			t.Errorf("normalizeZone(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestLoadRequiresNetbox(t *testing.T) {
	t.Setenv("NETBOX_URL", "")
	t.Setenv("NETBOX_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when NETBOX_URL is missing")
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("NETBOX_URL", "https://netbox.example.com")
	t.Setenv("NETBOX_TOKEN", "tok")
	// Ensure no stray overrides from the environment.
	for _, k := range []string{"SYNC_INTERVAL", "DNS_LISTEN_ADDR", "DNS_ZONE", "UPSTREAM_DNS", "UPSTREAM_ZONE", "METRICS_LISTEN_ADDR", "NETBOX_TXT_FORMAT"} {
		t.Setenv(k, "")
	}

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.SyncInterval != 10*time.Minute {
		t.Errorf("SyncInterval = %v; want 10m", c.SyncInterval)
	}
	if c.DNSZone != "asn.cymru.com." {
		t.Errorf("DNSZone = %q; want asn.cymru.com.", c.DNSZone)
	}
	if c.UpstreamZone != "asn.cymru.com." {
		t.Errorf("UpstreamZone = %q; want asn.cymru.com.", c.UpstreamZone)
	}
	if c.DNSListenAddr != ":53" {
		t.Errorf("DNSListenAddr = %q; want :53", c.DNSListenAddr)
	}
}

func TestLoadInvalidInterval(t *testing.T) {
	t.Setenv("NETBOX_URL", "https://netbox.example.com")
	t.Setenv("NETBOX_TOKEN", "tok")
	t.Setenv("SYNC_INTERVAL", "not-a-duration")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid SYNC_INTERVAL")
	}
}
