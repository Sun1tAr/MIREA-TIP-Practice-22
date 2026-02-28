package service

import (
	"errors"

	"github.com/sirupsen/logrus"
)

// Logger экспортируется для использования в http-хендлерах
var Logger *logrus.Logger

const (
	validUsername = "student"
	validPassword = "student"
	validToken    = "demo-token"
	subject       = "student"
)

func Login(username, password string) (string, error) {
	if username == validUsername && password == validPassword {
		return validToken, nil
	}
	return "", errors.New("invalid credentials")
}

func VerifyToken(token string) (bool, string) {
	if token == validToken {
		return true, subject
	}
	return false, ""
}
