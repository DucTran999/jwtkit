#!/bin/bash

# Output directory
KEY_DIR="./keys"

# Create directory if not exists
mkdir -p "$KEY_DIR"

# Generate 32-byte (256-bit) HMAC secret in hex, and save to file
openssl rand -hex 32 >"$KEY_DIR/secret.key"

# Optional: echo to confirm
echo "✅ HMAC secret written to $KEY_DIR/secret.key"
