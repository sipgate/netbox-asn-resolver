// Command netbox-asn-resolver is a DNS-to-ASN proxy: it answers TXT queries for
// ASNs from an in-memory cache synced from Netbox, falling back to an upstream
// resolver (e.g. Team Cymru) for public ASNs not present in Netbox.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rbott/netbox-asn-resolver/internal/cache"
	"github.com/rbott/netbox-asn-resolver/internal/config"
	"github.com/rbott/netbox-asn-resolver/internal/dnsserver"
	"github.com/rbott/netbox-asn-resolver/internal/metrics"
	"github.com/rbott/netbox-asn-resolver/internal/netbox"
	"github.com/rbott/netbox-asn-resolver/internal/syncer"
)

func main() {
	// Bootstrap logger at INFO; the level is raised/lowered to the configured
	// value once config has loaded (LevelVar lets us adjust after construction).
	levelVar := new(slog.LevelVar)
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: levelVar}))
	slog.SetDefault(log)

	cfg, err := config.Load()
	if err != nil {
		log.Error("configuration error", "error", err)
		os.Exit(1)
	}
	levelVar.Set(cfg.LogLevel)
	log.Debug("configuration loaded",
		"log_level", cfg.LogLevel.String(),
		"netbox_url", cfg.NetboxURL,
		"dns_listen_addr", cfg.DNSListenAddr,
		"dns_zone", cfg.DNSZone,
		"upstream_dns", cfg.UpstreamDNS,
		"upstream_zone", cfg.UpstreamZone,
		"sync_interval", cfg.SyncInterval.String())

	// Core dependencies.
	m := metrics.New()
	c := cache.New()
	nbClient := netbox.NewClient(cfg.NetboxURL, cfg.NetboxToken, log)
	sync := syncer.New(nbClient, c, m, log, cfg.TXTFormat)

	// Mandatory initial sync — fatal on failure (DNS must not serve empty).
	initCtx, initCancel := context.WithTimeout(context.Background(), 60*time.Second)
	if err := sync.InitialSync(initCtx); err != nil {
		initCancel()
		log.Error("initial Netbox sync failed; refusing to start", "error", err)
		os.Exit(1)
	}
	initCancel()
	log.Info("initial Netbox sync succeeded", "cached_asns", c.Len())

	// Root context cancelled on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Background sync loop.
	go sync.Run(ctx, cfg.SyncInterval)

	// Metrics HTTP server.
	metricsSrv := m.NewServer(cfg.MetricsListenAddr)
	go func() {
		log.Info("metrics server starting", "addr", cfg.MetricsListenAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server failed", "error", err)
			stop() // trigger shutdown of the rest
		}
	}()

	// DNS server.
	dnsSrv := dnsserver.New(dnsserver.Config{
		ListenAddr:   cfg.DNSListenAddr,
		Zone:         cfg.DNSZone,
		UpstreamDNS:  cfg.UpstreamDNS,
		UpstreamZone: cfg.UpstreamZone,
		TTL:          300,
	}, c, m, log)
	go func() {
		if err := dnsSrv.ListenAndServe(); err != nil {
			log.Error("dns server failed", "error", err)
			stop()
		}
	}()

	// Block until a signal (or a fatal server error) cancels the context.
	<-ctx.Done()
	log.Info("shutdown signal received, stopping servers")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), metrics.DefaultShutdownTimeout())
	defer cancel()

	if err := dnsSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("dns server shutdown error", "error", err)
	}
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("metrics server shutdown error", "error", err)
	}
	log.Info("shutdown complete")
}
