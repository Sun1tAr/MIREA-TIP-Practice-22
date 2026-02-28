package main

import (
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	grp "github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/auth/internal/grpc"
	httpHandler "github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/auth/internal/http"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/auth/internal/service"
	pb "github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/proto/auth"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/shared/logger"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/shared/middleware"
)

func main() {
	logrusLogger := logger.Init("auth")
	service.Logger = logrusLogger // для доступа из http-хендлера

	// Запуск HTTP сервера для логина (порт 8081)
	go func() {
		httpPort := os.Getenv("AUTH_HTTP_PORT")
		if httpPort == "" {
			httpPort = "8081"
		}

		mux := http.NewServeMux()
		mux.HandleFunc("POST /v1/auth/login", httpHandler.LoginHandler)

		handler := middleware.RequestIDMiddleware(mux)
		handler = middleware.LoggingMiddleware(handler)

		addr := ":" + httpPort
		logrusLogger.WithField("port", httpPort).Info("Auth HTTP server starting")
		if err := http.ListenAndServe(addr, handler); err != nil {
			logrusLogger.WithError(err).Fatal("HTTP server failed")
		}
	}()

	// Запуск gRPC сервера для Verify (порт 50051)
	grpcPort := os.Getenv("AUTH_GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "50051"
	}

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		logrusLogger.WithError(err).Fatal("failed to listen")
	}

	s := grpc.NewServer()
	pb.RegisterAuthServiceServer(s, &grp.Server{Logger: logrusLogger})
	reflection.Register(s)

	go func() {
		logrusLogger.WithField("port", grpcPort).Info("Auth gRPC server starting")
		if err := s.Serve(lis); err != nil {
			logrusLogger.WithError(err).Fatal("failed to serve")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logrusLogger.Info("Shutting down Auth server...")
	s.GracefulStop()
}
