package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server — HTTP endpoint Prometheus.
type Server struct {
	rt     *runtime.Runtime
	server *http.Server
	reg    *prometheus.Registry

	activeConns        prometheus.Gauge
	totalConns         prometheus.Counter
	uploadBytes        prometheus.Counter
	downloadBytes      prometheus.Counter
	replayAttacks      prometheus.Counter
	frontingConns      prometheus.Counter
	fakeTLSRejected    prometheus.Counter
	probeRequests      prometheus.Counter
	probeBlacklisted   prometheus.Counter
	tlsRejectReasons   *prometheus.CounterVec
	decoyRecords       prometheus.Counter
}

// New создаёт metrics server.
func New(rt *runtime.Runtime, cfg config.MetricsConfig) *Server {
	reg := prometheus.NewRegistry()
	s := &Server{rt: rt, reg: reg}

	s.activeConns = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "phantom_active_connections",
		Help: "Активные MTProto соединения",
	})
	s.totalConns = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phantom_connections_total",
		Help: "Всего установленных соединений",
	})
	s.uploadBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phantom_upload_bytes_total",
		Help: "Байт от клиентов",
	})
	s.downloadBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phantom_download_bytes_total",
		Help: "Байт к клиентам",
	})
	s.replayAttacks = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phantom_replay_attacks_total",
		Help: "Обнаруженные replay-атаки",
	})
	s.frontingConns = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phantom_fronting_connections_total",
		Help: "Domain fronting splice соединения",
	})
	s.fakeTLSRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phantom_fake_tls_rejected_total",
		Help: "Отклонённые Fake TLS handshake",
	})
	s.probeRequests = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phantom_probe_requests_total",
		Help: "Невалидные HTTP/TLS зонды (fallback/honeypot)",
	})
	s.probeBlacklisted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phantom_probe_blacklisted_total",
		Help: "Соединения, отклонённые probe blacklist",
	})
	s.tlsRejectReasons = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phantom_tls_reject_reason_total",
		Help: "Отклонённые handshake по причине",
	}, []string{"reason"})
	s.decoyRecords = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "phantom_decoy_records_total",
		Help: "Отправленные decoy TLS-записи",
	})

	reg.MustRegister(
		s.activeConns, s.totalConns, s.uploadBytes, s.downloadBytes,
		s.replayAttacks, s.frontingConns, s.fakeTLSRejected, s.probeRequests, s.probeBlacklisted,
		s.tlsRejectReasons, s.decoyRecords,
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	s.server = &http.Server{
		Addr:              cfg.Addr(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// ReplayAttacks возвращает counter для replay.
func (s *Server) ReplayAttacks() prometheus.Counter { return s.replayAttacks }

// FrontingConns возвращает counter для fronting.
func (s *Server) FrontingConns() prometheus.Counter { return s.frontingConns }

// FakeTLSRejected возвращает counter отклонённых Fake TLS.
func (s *Server) FakeTLSRejected() prometheus.Counter { return s.fakeTLSRejected }

// ProbeRequests возвращает counter зондирования.
func (s *Server) ProbeRequests() prometheus.Counter { return s.probeRequests }

// ProbeBlacklisted возвращает counter заблокированных probe IP.
func (s *Server) ProbeBlacklisted() prometheus.Counter { return s.probeBlacklisted }

// RecordTLSReject увеличивает счётчик отклонения по причине.
func (s *Server) RecordTLSReject(reason string) {
	if s != nil && s.tlsRejectReasons != nil {
		s.tlsRejectReasons.WithLabelValues(reason).Inc()
	}
}

// DecoyRecords возвращает counter decoy-записей.
func (s *Server) DecoyRecords() prometheus.Counter { return s.decoyRecords }

// Sync обновляет gauge/counter из stats tracker.
func (s *Server) Sync() {
	snap := s.rt.Stats.Snapshot()
	s.activeConns.Set(float64(snap.ActiveConnections))
}

// Serve запускает metrics HTTP.
func (s *Server) Serve(ctx context.Context) error {
	slog.Info("Prometheus слушает", "addr", s.server.Addr)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Sync()
			}
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()

	err := s.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// RecordTraffic обновляет счётчики трафика.
func (s *Server) RecordTraffic(upload, download int64) {
	if upload > 0 {
		s.uploadBytes.Add(float64(upload))
	}
	if download > 0 {
		s.downloadBytes.Add(float64(download))
	}
}

// Enabled проверяет, включены ли метрики.
func Enabled(cfg config.MetricsConfig) bool {
	return cfg.Port > 0
}

// AddrOrEmpty возвращает адрес или пустую строку.
func AddrOrEmpty(cfg config.MetricsConfig) string {
	if !Enabled(cfg) {
		return ""
	}
	return cfg.Addr()
}

// FormatAddr для логов.
func FormatAddr(cfg config.MetricsConfig) string {
	if !Enabled(cfg) {
		return "disabled"
	}
	return cfg.Addr()
}

// Validate проверяет конфиг метрик.
func Validate(cfg config.MetricsConfig) error {
	if cfg.Port < 0 {
		return fmt.Errorf("metrics.port не может быть отрицательным")
	}
	return nil
}
