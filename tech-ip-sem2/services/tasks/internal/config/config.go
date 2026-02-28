package config

import (
	"fmt"
	"os"
)

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	Driver   string // "postgres" или "sqlite3"
}

type Config struct {
	TasksPort    string
	AuthGRPCAddr string
	LogLevel     string
	DB           DatabaseConfig
}

func Load() (*Config, error) {
	cfg := &Config{
		TasksPort:    getEnv("TASKS_PORT", "8082"),
		AuthGRPCAddr: getEnv("AUTH_GRPC_ADDR", "localhost:50051"),
		LogLevel:     getEnv("LOG_LEVEL", "info"),
		DB: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "tasks_user"),
			Password: getEnv("DB_PASSWORD", "tasks_pass"),
			DBName:   getEnv("DB_NAME", "tasks_db"),
			Driver:   getEnv("DB_DRIVER", "postgres"),
		},
	}
	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func (db *DatabaseConfig) DSN() string {
	switch db.Driver {
	case "postgres":
		return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			db.Host, db.Port, db.User, db.Password, db.DBName)
	case "sqlite3":
		return fmt.Sprintf("%s.db", db.DBName) // Упрощенно
	default:
		return ""
	}
}
