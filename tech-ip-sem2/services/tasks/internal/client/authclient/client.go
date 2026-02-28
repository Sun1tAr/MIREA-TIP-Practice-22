package authclient

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	pb "github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/proto/auth"
	"github.com/sun1tar/MIREA-TIP-Practice-22/tech-ip-sem2/shared/middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Client struct {
	conn    *grpc.ClientConn
	client  pb.AuthServiceClient
	timeout time.Duration
	logger  *logrus.Logger
}

func NewClient(addr string, timeout time.Duration, logger *logrus.Logger) (*Client, error) {
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to auth service: %w", err)
	}

	return &Client{
		conn:    conn,
		client:  pb.NewAuthServiceClient(conn),
		timeout: timeout,
		logger:  logger,
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) VerifyToken(ctx context.Context, token string) (bool, string, error) {
	// Извлекаем request-id из контекста для прокидывания в gRPC метаданные
	requestID := middleware.GetRequestID(ctx)

	logEntry := c.logger.WithFields(logrus.Fields{
		"component":  "auth_client",
		"request_id": requestID,
	})

	logEntry.Debug("calling auth service Verify")

	// Создаём контекст с таймаутом
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Прокидываем request-id в метаданные gRPC
	if requestID != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", requestID)
	}

	resp, err := c.client.Verify(ctx, &pb.VerifyRequest{Token: token})
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			logEntry.WithError(err).Error("auth service unavailable")
			return false, "", fmt.Errorf("auth service unavailable: %w", err)
		}

		switch st.Code() {
		case codes.Unauthenticated:
			logEntry.WithField("token_present", token != "").Debug("token invalid")
			return false, "", nil
		case codes.DeadlineExceeded:
			logEntry.Warn("auth service timeout")
			return false, "", fmt.Errorf("auth service timeout")
		default:
			logEntry.WithFields(logrus.Fields{
				"code":  st.Code(),
				"error": st.Message(),
			}).Error("auth service error")
			return false, "", fmt.Errorf("auth service error: %v", st.Message())
		}
	}

	logEntry.WithFields(logrus.Fields{
		"valid":   resp.Valid,
		"subject": resp.Subject,
	}).Debug("auth response received")

	return resp.Valid, resp.Subject, nil
}
