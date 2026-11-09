// Command kauri-sync is the Kauri Sync server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/VizzleTF/kauri-sync/internal/api"
	"github.com/VizzleTF/kauri-sync/internal/clientip"
	"github.com/VizzleTF/kauri-sync/internal/events"
	"github.com/VizzleTF/kauri-sync/internal/ratelimit"
	"github.com/VizzleTF/kauri-sync/internal/store"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, log); err != nil {
		log.Error("kauri-sync stopped", "error", err)
		os.Exit(1)
	}
}

func healthcheck() int {
	port := env("PORT", "8296")
	c := &http.Client{Timeout: 4 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/readyz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func logLevel() slog.Level {
	var l slog.Level
	if l.UnmarshalText([]byte(env("LOG_LEVEL", "info"))) != nil {
		return slog.LevelInfo
	}
	return l
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// config is read from the environment; README lists every variable.
type config struct {
	databaseURL      string
	port             string
	maxBytesPerChain int64
	maxRecords       int64
	maxBlobBytes     int64
	maxBatchRecords  int
	maxBatchBytes    int64
	maxStreams       int
	tombstones       time.Duration
	forwards         time.Duration
	blobGrace        time.Duration
	chainsPerIP      int
	pairCodes        int
	pairJoins        int
	pairReads        int
	trustedProxy     string
	clientIPHeader   string
	accessLog        bool
}

func loadConfig() (config, error) {
	c := config{
		databaseURL:    os.Getenv("DATABASE_URL"),
		port:           env("PORT", "8296"),
		trustedProxy:   os.Getenv("TRUSTED_PROXY"),
		clientIPHeader: env("CLIENT_IP_HEADER", "X-Forwarded-For"),
		accessLog:      env("ACCESS_LOG", "true") == "true",
	}
	if c.databaseURL == "" {
		return c, errors.New("DATABASE_URL is required")
	}
	var err error
	sizes := []struct {
		name, def string
		dst       *int64
	}{
		{"MAX_BYTES_PER_CHAIN", "256MiB", &c.maxBytesPerChain},
		{"MAX_BLOB_BYTES", "16MiB", &c.maxBlobBytes},
		{"MAX_BATCH_BYTES", "8MiB", &c.maxBatchBytes},
	}
	for _, s := range sizes {
		if *s.dst, err = parseSize(env(s.name, s.def)); err != nil {
			return c, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	ints := []struct {
		name, def string
		dst       *int
	}{
		{"MAX_BATCH_RECORDS", "1000", &c.maxBatchRecords},
		{"MAX_EVENT_STREAMS", "20", &c.maxStreams},
		{"CHAINS_PER_IP_PER_HOUR", "10", &c.chainsPerIP},
		{"PAIR_CODES_PER_HOUR", "20", &c.pairCodes},
		{"PAIR_JOINS_PER_IP_PER_HOUR", "30", &c.pairJoins},
		{"PAIR_READS_PER_IP_PER_HOUR", "1200", &c.pairReads},
	}
	for _, s := range ints {
		if *s.dst, err = strconv.Atoi(env(s.name, s.def)); err != nil || *s.dst < 0 {
			return c, fmt.Errorf("%s must be a non-negative number", s.name)
		}
	}
	var records int
	if records, err = strconv.Atoi(env("MAX_RECORDS", "100000")); err != nil || records < 0 {
		return c, errors.New("MAX_RECORDS must be a non-negative number")
	}
	c.maxRecords = int64(records)
	durs := []struct {
		name, def string
		dst       *time.Duration
	}{
		{"TOMBSTONE_RETENTION", "30d", &c.tombstones},
		{"FORWARD_RETENTION", "90d", &c.forwards},
		{"BLOB_GRACE", "24h", &c.blobGrace},
	}
	for _, s := range durs {
		if *s.dst, err = parseDuration(env(s.name, s.def)); err != nil {
			return c, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return c, nil
}

func parseSize(s string) (int64, error) {
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		m      int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.m
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("want a size such as 256MiB")
	}
	return n * mult, nil
}

func parseDuration(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n < 0 {
			return 0, errors.New("want a duration such as 30d or 2h")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func limiter(perHour int) *ratelimit.Limiter {
	if perHour == 0 {
		return nil
	}
	return ratelimit.NewPer(perHour, time.Hour)
}

func run(ctx context.Context, log *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	trusted, err := clientip.ParsePrefixes(cfg.trustedProxy)
	if err != nil {
		return fmt.Errorf("TRUSTED_PROXY: %w", err)
	}
	pool, err := pgxpool.New(ctx, cfg.databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	st := store.New(pool)
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	hub := events.New(pool, log, cfg.maxStreams)
	go hub.Listen(ctx)
	go clean(ctx, st, log, store.Retention{Tombstones: cfg.tombstones, BlobGrace: cfg.blobGrace, Forwards: cfg.forwards, PairSlots: time.Hour})

	a := api.New(api.Config{
		Store: st, Hub: hub, Log: log,
		MaxBytesPerChain: cfg.maxBytesPerChain, MaxRecords: cfg.maxRecords, MaxBlobBytes: cfg.maxBlobBytes,
		MaxBatchRecords: cfg.maxBatchRecords, MaxBatchBytes: cfg.maxBatchBytes,
		ChainCreates: limiter(cfg.chainsPerIP), PairOpens: limiter(cfg.pairCodes),
		PairJoins: limiter(cfg.pairJoins), PairReads: limiter(cfg.pairReads),
	})
	mux := http.NewServeMux()
	mux.Handle("/v1/", a.Routes())
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	var ready atomic.Bool
	ready.Store(true)
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !ready.Load() || st.Ping(r.Context()) != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	var h http.Handler = mux
	if cfg.accessLog {
		h = accessLog(log, h)
	}
	h = clientip.New(trusted, cfg.clientIPHeader).Middleware(h)
	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("kauri-sync listening", "port", cfg.port, "version", version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	ready.Store(false)
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

func clean(ctx context.Context, st *store.Store, log *slog.Logger, r store.Retention) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := st.Clean(ctx, r); err != nil {
			log.Warn("cleanup failed", "error", err)
		} else {
			log.Debug("cleanup", "removed", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// accessLog logs method, route, status, time and sizes: never bodies, query
// strings, headers or client addresses.
func accessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		path := r.URL.Path
		if strings.HasPrefix(path, "/v1/pair/") {
			path = "/v1/pair/{slot}"
		} else if strings.HasPrefix(path, "/v1/blobs/") {
			path = "/v1/blobs/{id}"
		} else if strings.HasPrefix(path, "/v1/devices/") {
			path = "/v1/devices/{id}"
		}
		log.Info("request", "method", r.Method, "path", path, "status", rec.status,
			"ms", time.Since(start).Milliseconds(), "in", r.ContentLength, "out", rec.bytes)
	})
}
