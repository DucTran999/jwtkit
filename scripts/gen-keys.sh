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

# Set secure permissions
chmod 600 "$RSA_PRIVATE_KEY"
chmod 644 "$RSA_PUBLIC_KEY"

echo "✅ RSA key pair generated:"
echo "🔓 Public Key:  $RSA_PUBLIC_KEY"
echo "🔒 Private Key: $RSA_PRIVATE_KEY"

# Define ECDSA curves and output filenames
declare -A ECDSA_CURVES=(
    ["256"]="prime256v1" # ES256
    ["384"]="secp384r1"  # ES384
    ["512"]="secp521r1"  # ES512
)

# Generate ECDSA key pairs for all curves
for bits in "${!ECDSA_CURVES[@]}"; do
    curve="${ECDSA_CURVES[$bits]}"
    priv_key="$KEY_DIR/ecdsa_${bits}_private.pem"
    pub_key="$KEY_DIR/ecdsa_${bits}_public.pem"

    # Generate private key
    openssl ecparam -name "$curve" -genkey -noout -out "$priv_key"

    # Extract public key
    openssl ec -in "$priv_key" -pubout -out "$pub_key"

    # Set secure permissions
    chmod 600 "$priv_key"
    chmod 644 "$pub_key"

    echo "✅ ECDSA-${bits} key pair generated using curve $curve:"
    echo "🔓 Public Key:  $pub_key"
    echo "🔒 Private Key: $priv_key"
done
