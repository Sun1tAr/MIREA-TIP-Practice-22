package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/auth/internal/service"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/shared/middleware"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Message string `json:"message"`
}

// LoginHandler обрабатывает POST /v1/auth/login и устанавливает cookies
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	requestID := middleware.GetRequestID(r.Context())

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Проверка учётных данных (упрощённая)
	if req.Username != "student" || req.Password != "student" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Генерация session ID (в учебных целях - фиксированный)
	sessionID := "demo-session-123"

	// Генерация CSRF токена
	csrfToken := "demo-csrf-456"

	// Установка session cookie (HttpOnly, Secure, SameSite=Lax)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 час
	})

	// Установка CSRF cookie (НЕ HttpOnly, чтобы JS мог прочитать)
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})

	// Логирование
	if service.Logger != nil {
		service.Logger.WithField("request_id", requestID).Info("login successful, cookies set")
	}

	// Ответ (без токена в теле, только подтверждение)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loginResponse{
		Message: "login successful, cookies set",
	})
}
