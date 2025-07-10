package jwtkit

import (
	"github.com/golang-jwt/jwt/v5"
)

// JWT defines the interface for signing and parsing JWT tokens.
// It abstracts the underlying signing method (e.g., HMAC, RSA, etc.).
type JWT interface {
	// Sign generates a signed JWT string from the given claims.
	// The claims must implement the jwt.Claims interface (e.g., jwt.MapClaims, custom claims structs).
	// Returns the signed JWT as a string.
	Sign(claims jwt.Claims) (string, error)

	// Parse verifies the token's signature and parses its claims.
	// Returns the token's claims as jwt.MapClaims if valid.
	// Useful for generic claim parsing when you don't have a custom claim struct.
	Parse(token string) (*jwt.MapClaims, error)

	// ParseInto parses the JWT string into the provided destination claims struct.
	// The destination must implement jwt.Claims (e.g., a custom claims struct with embedded jwt.RegisteredClaims).
	// Useful when working with strongly-typed custom claims.
	ParseInto(tokenStr string, dest jwt.Claims) error
}
