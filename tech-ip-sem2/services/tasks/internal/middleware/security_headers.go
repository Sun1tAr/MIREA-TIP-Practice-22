package middleware

import "net/http"

// SecurityHeadersMiddleware добавляет заголовки безопасности
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Запрет на определение MIME-типа из содержимого
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Защита от clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Простая CSP (только для демонстрации)
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// HSTS (только для HTTPS)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}
