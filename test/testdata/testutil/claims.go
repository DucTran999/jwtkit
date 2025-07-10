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
