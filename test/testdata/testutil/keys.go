package testutil

import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// LoadRSAKey reads RSA private and public keys from PEM files and parses them.
// Returns both keys or an error if any step fails.
func LoadRSAKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Read the private key PEM file
	privPem, err := os.ReadFile("./keys/rsa_private.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse the private key
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(privPem)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Read the public key PEM file
	pubPem, err := os.ReadFile("./keys/rsa_public.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %w", err)
	}

	// Parse the public key
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(pubPem)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return signKey, verifyKey, nil
}
