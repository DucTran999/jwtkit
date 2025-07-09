package jwtkit

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type SigningAlgorithm string

const (
	HS256 SigningAlgorithm = "HS256"
	HS384 SigningAlgorithm = "HS384"
	HS512 SigningAlgorithm = "HS512"

	RS256 SigningAlgorithm = "RS256"
	RS384 SigningAlgorithm = "RS384"
	RS512 SigningAlgorithm = "RS512"

	ES256 SigningAlgorithm = "ES256"
	ES384 SigningAlgorithm = "ES384"
	ES512 SigningAlgorithm = "ES512"

	EdDSA SigningAlgorithm = "EdDSA"
)

// jwtMethods maps custom SigningAlgorithm identifiers to the corresponding
// jwt.SigningMethod implementations supported by the github.com/golang-jwt/jwt/v5 package.
// This allows flexible parsing and signing of JWTs using a variety of algorithms,
// including HMAC, RSA, ECDSA, and EdDSA.
var jwtMethods = map[SigningAlgorithm]jwt.SigningMethod{
	// HMAC algorithms
	HS256: jwt.SigningMethodHS256,
	HS384: jwt.SigningMethodHS384,
	HS512: jwt.SigningMethodHS512,

	// RSA algorithms
	RS256: jwt.SigningMethodRS256,
	RS384: jwt.SigningMethodRS384,
	RS512: jwt.SigningMethodRS512,

	// ECDSA algorithms
	ES256: jwt.SigningMethodES256,
	ES384: jwt.SigningMethodES384,
	ES512: jwt.SigningMethodES512,

	// Edwards-curve Digital Signature Algorithm
	EdDSA: jwt.SigningMethodEdDSA,
}

// ToJWTMethod converts a custom SigningAlgorithm to its corresponding jwt.SigningMethod.
//
// It normalizes the input (uppercase, trimmed), then looks up the algorithm in the jwtMethods map.
//   - Example: hs256 -> HS256
//
// Returns an error if the algorithm is not supported.
func (a SigningAlgorithm) ToJWTMethod() (jwt.SigningMethod, error) {
	cleaned := SigningAlgorithm(strings.ToUpper(strings.TrimSpace(string(a))))
	if method, ok := jwtMethods[cleaned]; ok {
		return method, nil
	}
	return nil, ErrInvalidAlgorithm
}
