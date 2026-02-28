package logger

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger - глобальный экземпляр логгера (можно заменить на zap)
var Logger *logrus.Logger

// Init инициализирует структурированный логгер
func Init(serviceName string) *logrus.Logger {
	Logger = logrus.New()

	// Настройка вывода
	Logger.SetOutput(os.Stdout)

	// Формат JSON для структурированного логирования
	Logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "ts",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	// Уровень логирования (можно через ENV)
	level := os.Getenv("LOG_LEVEL")
	if level != "" {
		lvl, err := logrus.ParseLevel(level)
		if err == nil {
			Logger.SetLevel(lvl)
		}
	} else {
		Logger.SetLevel(logrus.InfoLevel)
	}

	// Добавляем поле service во все логи
	Logger = Logger.WithField("service", serviceName).Logger

	return Logger
}

// WithRequestID добавляет request-id в контекст логгера
func WithRequestID(logger *logrus.Logger, requestID string) *logrus.Entry {
	if requestID == "" {
		return logrus.NewEntry(logger)
	}
	return logger.WithField("request_id", requestID)
}
