#!/bin/bash

set -euo pipefail

# Output directory
KEY_DIR="./keys"

# Create directory if not exists
mkdir -p "$KEY_DIR"

# Generate 32-byte (256-bit) HMAC secret in hex, and save to file
openssl rand -hex 32 >"$KEY_DIR/secret.key"

# Optional: echo to confirm
echo "✅ HMAC secret written to $KEY_DIR/secret.key"

chmod 600 "$KEY_DIR/secret.key"

# Generate rsa keys
RSA_PRIVATE_KEY="$KEY_DIR/rsa_private.pem"
RSA_PUBLIC_KEY="$KEY_DIR/rsa_public.pem"

# Generate RSA private key (2048 bits is secure, 4096 is stronger)
openssl genpkey -algorithm RSA -out "$RSA_PRIVATE_KEY" -pkeyopt rsa_keygen_bits:2048

# Extract public key from private key
openssl rsa -pubout -in "$RSA_PRIVATE_KEY" -out "$RSA_PUBLIC_KEY"

echo "✅ RSA key pair generated:"
echo "🔓 Public Key:  $RSA_PUBLIC_KEY"
echo "🔒 Private Key: $RSA_PRIVATE_KEY"
