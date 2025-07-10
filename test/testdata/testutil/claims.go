package testutil

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func DefaultClaims() jwt.MapClaims {
	claims := jwt.MapClaims{
		"id":  "uuid-1",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	return claims
}

type MyCustomClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func DefaultMyCustomClaims() *MyCustomClaims {
	return &MyCustomClaims{
		UserID: "uuid-1234",
		Role:   "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    "my-app",
		},
	}
}
