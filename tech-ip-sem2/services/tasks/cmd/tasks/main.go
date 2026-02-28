package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/shared/logger"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/shared/middleware"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/client/authclient"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/config"
	handlers "github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/http"
	customMiddleware "github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/middleware"
	metricsMiddleware "github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/middleware"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/repository"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/tasks/internal/service"
)

func main() {
	logrusLogger := logger.Init("tasks")

	cfg, err := config.Load()
	if err != nil {
		logrusLogger.WithError(err).Fatal("failed to load config")
	}

	// Инициализация репозитория
	var repo repository.TaskRepository
	if cfg.DB.Driver == "postgres" {
		postgresRepo, err := repository.NewPostgresTaskRepository(cfg.DB.DSN())
		if err != nil {
			logrusLogger.WithError(err).Fatal("failed to connect to database")
		}
		defer postgresRepo.Close()
		repo = postgresRepo
	} else {
		logrusLogger.Fatal("unsupported database driver: " + cfg.DB.Driver)
	}

	// Инициализация клиента Auth (для совместимости, но теперь не используется)
	authClient, err := authclient.NewClient(cfg.AuthGRPCAddr, 2*time.Second, logrusLogger)
	if err != nil {
		logrusLogger.WithError(err).Fatal("failed to create auth client")
	}
	defer authClient.Close()

	// Инициализация сервиса
	taskService := service.NewTaskService(repo)

	// Инициализация хендлера
	taskHandler := handlers.NewTaskHandler(taskService, authClient, logrusLogger)

	// Настройка роутера
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/tasks", taskHandler.CreateTask)
	mux.HandleFunc("GET /v1/tasks", taskHandler.ListTasks)
	mux.HandleFunc("GET /v1/tasks/{id}", taskHandler.GetTask)
	mux.HandleFunc("PATCH /v1/tasks/{id}", taskHandler.UpdateTask)
	mux.HandleFunc("DELETE /v1/tasks/{id}", taskHandler.DeleteTask)
	mux.HandleFunc("GET /v1/tasks/search", taskHandler.SearchTasks)
	mux.Handle("GET /metrics", metricsMiddleware.MetricsHandler())

	// Цепочка middleware (порядок важен!)
	handler := middleware.RequestIDMiddleware(mux)                // 1. request-id
	handler = customMiddleware.SecurityHeadersMiddleware(handler) // 2. заголовки безопасности
	handler = customMiddleware.CSRFMiddleware(handler)            // 3. CSRF защита
	handler = metricsMiddleware.MetricsMiddleware(handler)        // 4. метрики
	handler = middleware.LoggingMiddleware(handler)               // 5. логирование

	addr := fmt.Sprintf(":%s", cfg.TasksPort)
	logrusLogger.WithField("port", cfg.TasksPort).Info("tasks service starting")
	if err := http.ListenAndServe(addr, handler); err != nil {
		logrusLogger.WithError(err).Fatal("server failed")
	}
}
