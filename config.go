package jwtkit

import (
	"bytes"
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
}

// GetKeyPairs returns the appropriate key pair (private and public) for the given signing algorithm.
//   - For HMAC (HS256, HS384, HS512), it returns the shared secret key for both signing and verification.
//   - For RSA (RS256, etc.), it returns the private key for signing and the public key for verification.
//
// Returns an error if required keys are missing.
func (c *Config) GetKeyPairs(alg jwt.SigningMethod) (any, any, error) {
	switch alg.Alg() {
	// HMAC algorithms use a single shared secret key
	case jwt.SigningMethodHS256.Alg(), jwt.SigningMethodHS384.Alg(), jwt.SigningMethodHS512.Alg():
		if len(c.Secret) == 0 {
			return nil, nil, ErrMissingKey
		}
		// Trim any whitespace to avoid accidental padding
		secret := bytes.TrimSpace(c.Secret)
		return secret, secret, nil

	default:
		// For asymmetric algorithms like RSA
		if c.RSAPublic == nil || c.RSAPrivate == nil {
			return nil, nil, ErrMissingKey
		}
		return c.RSAPrivate, c.RSAPublic, nil
	}
}
