package jwtkit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
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

	// EdDSA Algorithm (Ed25519)
	EDPrivate ed25519.PrivateKey
	EDPublic  ed25519.PublicKey
}

// GetKeyPairs returns the appropriate key pair for the given JWT signing algorithm.
//   - HMAC (HS*): Returns the same secret for signing and verification.
//   - ECDSA (ES*): Returns ECDSA private and public keys.
//   - EdDSA (Ed25519): Returns Ed25519 private and public keys.
//   - RSA (RS*): Returns RSA private and public keys.
func (c *Config) GetKeyPairs(alg jwt.SigningMethod) (any, any, error) {
	switch alg.Alg() {

	// HMAC algorithms use a single shared secret key
	case jwt.SigningMethodHS256.Alg(), jwt.SigningMethodHS384.Alg(), jwt.SigningMethodHS512.Alg():
		if len(c.Secret) == 0 {
			return nil, nil, ErrMissingKey
		}
		// Trim any accidental padding/whitespace
		secret := bytes.TrimSpace(c.Secret)
		return secret, secret, nil

	// ECDSA algorithms use EC private/public key pair
	case jwt.SigningMethodES256.Alg(), jwt.SigningMethodES384.Alg(), jwt.SigningMethodES512.Alg():
		if c.ESPrivate == nil || c.ESPublic == nil {
			return nil, nil, ErrMissingKey
		}
		return c.ESPrivate, c.ESPublic, nil

	// EdDSA algorithm (Ed25519) uses ed25519 private/public key pair
	case jwt.SigningMethodEdDSA.Alg():
		if len(c.EDPrivate) == 0 || len(c.EDPublic) == 0 {
			return nil, nil, ErrMissingKey
		}
		return c.EDPrivate, c.EDPublic, nil

	// RSA algorithms use RSA private/public key pair
	default:
		if c.RSAPrivate == nil || c.RSAPublic == nil {
			return nil, nil, ErrMissingKey
		}
		return c.RSAPrivate, c.RSAPublic, nil
	}
}
