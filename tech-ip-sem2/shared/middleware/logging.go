package middleware

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/shared/logger"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware логирует каждый HTTP запрос в структурированном формате
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Получаем request-id из контекста
		requestID := GetRequestID(r.Context())

		// Создаём entry с request-id
		logEntry := logger.WithRequestID(logger.Logger, requestID)

		// Логируем начало запроса (опционально, на DEBUG уровне)
		logEntry.Debugf("request started: %s %s", r.Method, r.URL.Path)

		// Обрабатываем запрос
		next.ServeHTTP(wrapped, r)

		// Логируем завершение запроса
		duration := time.Since(start)
		logEntry.WithFields(logrus.Fields{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      wrapped.statusCode,
			"duration_ms": duration.Milliseconds(),
			"remote_ip":   r.RemoteAddr,
			"user_agent":  r.UserAgent(),
		}).Info("request completed")
	})
}
