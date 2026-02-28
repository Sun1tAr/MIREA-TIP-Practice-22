package grpc

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/auth/internal/service"
	pb "github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/proto/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Server struct {
	pb.UnimplementedAuthServiceServer
	Logger *logrus.Logger
}

func (s *Server) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	// Извлекаем request-id из входящих метаданных
	var requestID string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get("x-request-id"); len(values) > 0 {
			requestID = values[0]
		}
	}

	logEntry := s.Logger.WithFields(logrus.Fields{
		"component":     "grpc_server",
		"request_id":    requestID,
		"token_present": req.Token != "",
	})

	valid, subject := service.VerifyToken(req.Token)
	if !valid {
		logEntry.Warn("invalid token attempt")
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	logEntry.WithField("subject", subject).Info("token verified successfully")

	return &pb.VerifyResponse{
		Valid:   true,
		Subject: subject,
	}, nil
}
