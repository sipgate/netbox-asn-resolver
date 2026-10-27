// Package netbox provides a thin client for the native Netbox ASN endpoint
// (/api/ipam/asns/) and the routine that syncs ASN data into an in-memory
// cache consumed by the DNS server.
package netbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NestedRef mirrors a Netbox "brief" nested object (rir, tenant, ...).
type NestedRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// ASN mirrors the relevant fields of a native Netbox ASN object as returned
// by /api/ipam/asns/. Extend this struct as you add placeholders to the
// configurable TXT format.
type ASN struct {
	ID          int        `json:"id"`
	ASN         int64      `json:"asn"`
	Description string     `json:"description"`
	RIR         *NestedRef `json:"rir"`
	Tenant      *NestedRef `json:"tenant"`
	Created     string     `json:"created"`      // ISO-8601, e.g. "2023-01-15T10:30:00.123456Z"
	LastUpdated string     `json:"last_updated"` // ISO-8601
}

// listResponse is the paginated envelope Netbox wraps list results in.
type listResponse struct {
	Count   int             `json:"count"`
	Next    string          `json:"next"`
	Results json.RawMessage `json:"results"`
}

// Client talks to a Netbox instance using a token.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
	pageSize   int
	log        *slog.Logger
}

// NewClient constructs a Netbox client. baseURL may include or omit a trailing
// slash; it should be the scheme+host root (e.g. "https://netbox.example.com").
// A nil logger falls back to slog.Default().
func NewClient(baseURL, token string, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		pageSize:   1000,
		log:        log,
	}
}

// FetchASNs retrieves every ASN object from Netbox, following pagination.
// The provided context bounds the entire operation; callers should use a
// timeout so a hung Netbox cannot block startup or a sync cycle indefinitely.
func (c *Client) FetchASNs(ctx context.Context) ([]ASN, error) {
	// Build the first page URL.
	u, err := url.Parse(c.baseURL + "/api/ipam/asns/")
	if err != nil {
		return nil, fmt.Errorf("invalid NETBOX_URL: %w", err)
	}
	q := u.Query()
	q.Set("limit", fmt.Sprintf("%d", c.pageSize))
	u.RawQuery = q.Encode()
	next := u.String()

	c.log.Debug("fetching ASNs from netbox", "url", next, "page_size", c.pageSize)

	var all []ASN
	page := 0
	for next != "" {
		results, nextURL, err := c.fetchPage(ctx, next)
		if err != nil {
			return nil, err
		}
		page++
		c.log.Debug("netbox page fetched", "page", page, "in_page", len(results), "total", len(all)+len(results), "has_next", nextURL != "")
		all = append(all, results...)
		next = nextURL
	}
	c.log.Debug("netbox fetch complete", "pages", page, "asns", len(all))
	return all, nil
}

func (c *Client) fetchPage(ctx context.Context, pageURL string) ([]ASN, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+c.token)
	req.Header.Set("Accept", "application/json")

	c.log.Debug("netbox API request", "method", http.MethodGet, "url", pageURL)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request %s: %w", pageURL, err)
	}
	defer resp.Body.Close()

	c.log.Debug("netbox API response", "url", pageURL, "status", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("netbox returned status %d for %s", resp.StatusCode, pageURL)
	}

	var env listResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, "", fmt.Errorf("decode response: %w", err)
	}

	var results []ASN
	if err := json.Unmarshal(env.Results, &results); err != nil {
		return nil, "", fmt.Errorf("decode results: %w", err)
	}

	return results, env.Next, nil
}
