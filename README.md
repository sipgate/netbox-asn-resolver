# netbox-asn-resolver

A lightweight DNS-to-ASN proxy. It answers TXT queries like `AS13335.<zone>`
from an in-memory cache synced from Netbox's native ASN database, falling back to
an upstream resolver (e.g. Team Cymru) for public ASNs not present in Netbox.

## How resolution works

Every TXT query for `AS<n>.<zone>` (or `<n>.<zone>`) runs through a three-step
pipeline in `internal/dnsserver`:

1. **Cache hit** - if the ASN is in the Netbox-synced cache, answer with its
   formatted TXT record.
2. **Private-ASN filter** - otherwise, RFC6996 private ASNs (16-bit
   `64512-65534`, 32-bit `4200000000-4294967294`) get NXDOMAIN and are **never**
   forwarded upstream.
3. **Upstream fallback** - public ASNs are queried against `UPSTREAM_DNS` as
   `AS<n>.<UPSTREAM_ZONE>` (default `asn.cymru.com.`) and the TXT answer is
   forwarded under the original name.

## Build & run

```sh
go mod tidy        # populate go.sum
go build -o netbox-asn-resolver .
go test ./...      # unit tests for config, syncer, and the DNS pipeline
NETBOX_URL=https://netbox.example.com NETBOX_TOKEN=... ./netbox-asn-resolver
```

## Configuration

| Env var               | Default                                        | Notes                          |
| --------------------- | ---------------------------------------------- | ------------------------------ |
| `NETBOX_URL`          | -                                              | required                       |
| `NETBOX_TOKEN`        | -                                              | required                       |
| `SYNC_INTERVAL`       | `10m`                                          | Go duration                    |
| `DNS_LISTEN_ADDR`     | `:53`                                          | UDP + TCP                      |
| `DNS_ZONE`            | `asn.cymru.com.`                            | trailing dot enforced          |
| `UPSTREAM_DNS`        | `8.8.8.8:53`                                   | upstream for public fallback   |
| `UPSTREAM_ZONE`       | `asn.cymru.com.`                               | zone queried upstream          |
| `METRICS_LISTEN_ADDR` | `:2112`                                        | Prometheus `/metrics`          |
| `LOG_LEVEL`           | `info`                                         | `debug`/`info`/`warn`/`error`  |
| `NETBOX_TXT_FORMAT`   | `%{asn} \| %{rir.name} \| netbox \| %{created} \| %{description}` | response template |

### `NETBOX_TXT_FORMAT` placeholders

`%{...}` placeholders map to native Netbox ASN fields; unknown keys render empty.

| Placeholder      | Source                                                        |
| ---------------- | ------------------------------------------------------------- |
| `%{asn}`         | ASN number                                                    |
| `%{id}`          | Netbox object ID                                              |
| `%{description}` | ASN description                                               |
| `%{created}`     | creation date, trimmed to `YYYY-MM-DD` (Team Cymru style)     |
| `%{last_updated}`| last-modified date, trimmed to `YYYY-MM-DD`                   |
| `%{rir.id}` / `%{rir.name}` / `%{rir.slug}`          | RIR (nil -> empty)         |
| `%{tenant.id}` / `%{tenant.name}` / `%{tenant.slug}` | tenant (nil -> empty)      |
