package jwtkit

import (
	"bytes"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	Alg SigningAlgorithm

	// HMAC
	Secret []byte
}

func (c *Config) GetKeyPairs(alg jwt.SigningMethod) (any, any, error) {
	switch alg.Alg() {
	case jwt.SigningMethodHS256.Alg(), jwt.SigningMethodHS384.Alg(), jwt.SigningMethodHS512.Alg():
		if len(c.Secret) == 0 {
			return nil, nil, ErrMissingKey
		}
		secret := bytes.TrimSpace(c.Secret)
		return secret, secret, nil

	default:
		return nil, nil, ErrInvalidAlgorithm
	}
}
