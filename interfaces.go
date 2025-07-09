package jwtkit

import (
	"github.com/golang-jwt/jwt/v5"
)

// JWT defines the interface for signing and parsing JWT tokens.
// It abstracts the underlying signing method (e.g., HMAC, RSA, etc.)
type JWT interface {
	// Sign generates a signed JWT string from the given claims.
	// The claims must implement the jwt.Claims interface (e.g., jwt.MapClaims).
	Sign(claims jwt.Claims) (string, error)

	// Parse verifies the token's signature and parses its claims.
	// Returns the token's claims as jwt.MapClaims if valid.
	Parse(token string) (*jwt.MapClaims, error)
}
