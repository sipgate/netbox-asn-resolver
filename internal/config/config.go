// Package config loads runtime configuration from environment variables
// following the 12-Factor App methodology.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all runtime configuration for the ASN proxy.
type Config struct {
	// Netbox connection.
	NetboxURL    string        // e.g. "https://netbox.example.com"
	NetboxToken  string        // API token (Authorization: Token <token>)
	SyncInterval time.Duration // how often to re-sync the cache from Netbox

	// DNS server.
	DNSListenAddr string // e.g. ":53"
	DNSZone       string // fully-qualified, trailing dot, e.g. "asn.cymru.com."
	UpstreamDNS   string // e.g. "8.8.8.8:53"
	UpstreamZone  string // zone queried upstream for public ASNs, e.g. "asn.cymru.com."

	// Metrics server.
	MetricsListenAddr string // e.g. ":2112"

	// Response formatting. Supports placeholders matching Netbox ASN object
	// fields, e.g. "%{asn} | %{rir.name} | netbox | %{description}".
	TXTFormat string
}

// Load reads configuration from the environment, applies defaults, and
// validates that required values are present.
func Load() (*Config, error) {
	c := &Config{
		NetboxURL:         os.Getenv("NETBOX_URL"),
		NetboxToken:       os.Getenv("NETBOX_TOKEN"),
		DNSListenAddr:     envDefault("DNS_LISTEN_ADDR", ":53"),
		MetricsListenAddr: envDefault("METRICS_LISTEN_ADDR", ":2112"),
		DNSZone:           normalizeZone(envDefault("DNS_ZONE", "asn.cymru.com.")),
		UpstreamDNS:       envDefault("UPSTREAM_DNS", "8.8.8.8:53"),
		UpstreamZone:      normalizeZone(envDefault("UPSTREAM_ZONE", "asn.cymru.com.")),
		TXTFormat:         envDefault("NETBOX_TXT_FORMAT", "%{asn} | %{rir.name} | netbox | %{created} | %{description}"),
	}

	interval, err := time.ParseDuration(envDefault("SYNC_INTERVAL", "10m"))
	if err != nil {
		return nil, fmt.Errorf("invalid SYNC_INTERVAL: %w", err)
	}
	c.SyncInterval = interval

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.NetboxURL == "" {
		return fmt.Errorf("NETBOX_URL is required")
	}
	if c.NetboxToken == "" {
		return fmt.Errorf("NETBOX_TOKEN is required")
	}
	if c.SyncInterval <= 0 {
		return fmt.Errorf("SYNC_INTERVAL must be positive")
	}
	return nil
}

// envDefault returns the value of the named env var, or def if it is unset/empty.
func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// normalizeZone ensures the zone is lower-cased and fully-qualified with a
// trailing dot, which is how miekg/dns presents query names.
func normalizeZone(zone string) string {
	zone = strings.ToLower(strings.TrimSpace(zone))
	if zone != "" && !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	return zone
}
