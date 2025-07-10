package jwtkit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	Alg SigningAlgorithm

	// HMAC
	Secret []byte

	// RSA Algorithm
	RSAPrivate *rsa.PrivateKey
	RSAPublic  *rsa.PublicKey

	// ECDSA Algorithm
	ESPrivate *ecdsa.PrivateKey
	ESPublic  *ecdsa.PublicKey
}

// GetKeyPairs returns the appropriate key pair for the given JWT signing algorithm.
//   - HMAC (HS*): Returns the same secret for signing and verification.
//   - ECDSA (ES*): Returns ECDSA private and public keys.
//   - RSA (RS*): Returns RSA private and public keys.
func (c *Config) GetKeyPairs(alg jwt.SigningMethod) (any, any, error) {
	switch alg.Alg() {
	// HMAC algorithms use a single shared secret key
	case jwt.SigningMethodHS256.Alg(), jwt.SigningMethodHS384.Alg(), jwt.SigningMethodHS512.Alg():
		if len(c.Secret) == 0 {
			return nil, nil, ErrMissingKey
		}
		secret := bytes.TrimSpace(c.Secret)
		return secret, secret, nil

	// ECDSA algorithms use EC private/public key pair
	case jwt.SigningMethodES256.Alg(), jwt.SigningMethodES384.Alg(), jwt.SigningMethodES512.Alg():
		if c.ESPrivate == nil || c.ESPublic == nil {
			return nil, nil, ErrMissingKey
		}
		return c.ESPrivate, c.ESPublic, nil

	// RSA algorithms use RSA private/public key pair
	default:
		if c.RSAPublic == nil || c.RSAPrivate == nil {
			return nil, nil, ErrMissingKey
		}
		return c.RSAPrivate, c.RSAPublic, nil
	}
}
