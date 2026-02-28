package middleware

import (
	"net/http"
)

// CSRFMiddleware проверяет CSRF-токен для state-changing методов
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Только для POST, PATCH, DELETE
		if r.Method == http.MethodPost || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			// Получаем CSRF токен из cookie
			csrfCookie, err := r.Cookie("csrf_token")
			if err != nil {
				http.Error(w, `{"error":"CSRF token missing in cookies"}`, http.StatusForbidden)
				return
			}

			// Получаем CSRF токен из заголовка
			csrfHeader := r.Header.Get("X-CSRF-Token")
			if csrfHeader == "" {
				http.Error(w, `{"error":"X-CSRF-Token header missing"}`, http.StatusForbidden)
				return
			}

			// Сравниваем
			if csrfCookie.Value != csrfHeader {
				// Можно добавить логирование попытки
				http.Error(w, `{"error":"CSRF token mismatch"}`, http.StatusForbidden)
				return
			}
		}

		// Если проверка пройдена или метод безопасный, передаём дальше
		next.ServeHTTP(w, r)
	})
}
