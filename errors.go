package jwtkit

import (
	"errors"
)

var (
	// ErrParseToken is returned when the JWT token cannot be parsed or is malformed.
	ErrParseToken = errors.New("jwtkit: failed to parse token")

	// ErrMissingKey is returned when a signing or verification key is not provided.
	ErrMissingKey = errors.New("jwtkit: missing signing or verification key")

	// ErrInvalidAlgorithm indicates that the provided signing algorithm is unsupported or unknown.
	ErrInvalidAlgorithm = errors.New("jwtkit: unsupported or unknown signing algorithm")

	// ErrInvalidTokenSignature is returned when the token signature does not match or is tampered with.
	ErrInvalidTokenSignature = errors.New("jwtkit: invalid or tampered token signature")

	// ErrAlgorithmNotMatch is returned when the token's algorithm does not match the configured signing method.
	ErrAlgorithmNotMatch = errors.New("token algorithm does not match expected signing method")
)
