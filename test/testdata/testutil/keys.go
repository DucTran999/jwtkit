package testutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

// LoadECDSAKeys reads ECDSA private and public keys from PEM files and parses them.
// Returns both keys or an error if any step fails.
func LoadECDSAKeys(pubFile, privFile string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	// Read the private key PEM file
	privPem, err := os.ReadFile("./keys/" + privFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse the private key
	signKey, err := jwt.ParseECPrivateKeyFromPEM(privPem)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Read the public key PEM file
	pubPem, err := os.ReadFile("./keys/" + pubFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %w", err)
	}

	// Parse the public key
	verifyKey, err := jwt.ParseECPublicKeyFromPEM(pubPem)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return signKey, verifyKey, nil
}

// LoadEd25519Keys reads Ed25519 private and public keys from PEM files and parses them.
// Returns both keys or an error if any step fails.
func LoadEd25519Keys() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	// Read the private key PEM file
	privPem, err := os.ReadFile("./keys/ed25519_private.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}
	privBlock, _ := pem.Decode(privPem)
	if privBlock == nil || privBlock.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("invalid private key PEM format")
	}

	privKeyRaw, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privKey, ok := privKeyRaw.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an ed25519 private key")
	}

	// Read the public key PEM file
	pubPem, err := os.ReadFile("./keys/ed25519_public.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %w", err)
	}
	pubBlock, _ := pem.Decode(pubPem)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		return nil, nil, fmt.Errorf("invalid public key PEM format")
	}

	pubKeyRaw, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	pubKey, ok := pubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an ed25519 public key")
	}

	return privKey, pubKey, nil
}
