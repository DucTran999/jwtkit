package testutil

import (
	"errors"
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

type BrokenClaims string

func (c BrokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return nil, errors.New("audience missing")
}

func (c BrokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return nil, errors.New("expiration missing")
}

func (c BrokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return nil, errors.New("issued at missing")
}

func (c BrokenClaims) GetIssuer() (string, error) {
	return "", errors.New("issuer missing")
}

func (c BrokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, errors.New("not before missing")
}

func (c BrokenClaims) GetSubject() (string, error) {
	return "", errors.New("subject missing")
}
