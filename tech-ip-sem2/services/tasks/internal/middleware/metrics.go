package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Определяем метрики
var (
	// Счётчик запросов по методу, пути и статусу
	requestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "route", "status"},
	)

	// Гистограмма длительности запросов
	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: []float64{0.01, 0.05, 0.1, 0.3, 1, 3}, // учебные бакеты
		},
		[]string{"method", "route"},
	)

	// Текущее количество активных запросов
	inFlightRequests = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_in_flight_requests",
			Help: "Current number of in-flight HTTP requests",
		},
	)
)

// MetricsMiddleware собирает метрики для каждого HTTP запроса
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Увеличиваем счётчик активных запросов
		inFlightRequests.Inc()
		defer inFlightRequests.Dec()

		// Нормализуем путь для меток (заменяем динамические ID на {id})
		route := normalizeRoute(r.URL.Path)
		method := r.Method

		// Засекаем время начала
		start := time.Now()

		// Оборачиваем ResponseWriter для захвата статуса
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Выполняем следующий обработчик
		next.ServeHTTP(wrapped, r)

		// Вычисляем длительность
		duration := time.Since(start).Seconds()

		// Сохраняем метрики
		status := strconv.Itoa(wrapped.statusCode)
		requestsTotal.WithLabelValues(method, route, status).Inc()
		requestDuration.WithLabelValues(method, route).Observe(duration)
	})
}

// responseWriter обёртка для захвата статус-кода
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// normalizeRoute заменяет динамические ID на плейсхолдеры для метрик
func normalizeRoute(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		// Если часть пути похожа на ID (начинается с t_ или число)
		if strings.HasPrefix(part, "t_") || (len(part) > 0 && part[0] >= '0' && part[0] <= '9') {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

// MetricsHandler возвращает HTTP handler для /metrics
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
