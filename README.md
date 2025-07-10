# 🔐 jwtkit

[![Go Report Card](https://goreportcard.com/badge/github.com/DucTran999/jwtkit)](https://goreportcard.com/report/github.com/DucTran999/jwtkit)
[![Go](https://img.shields.io/badge/Go-1.23-blue?logo=go)](https://golang.org)
[![CI](https://github.com/DucTran999/jwtkit/actions/workflows/ci.yml/badge.svg)](https://github.com/DucTran999/jwtkit/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/DucTran999/jwtkit/branch/master/graph/badge.svg)](https://codecov.io/gh/DucTran999/jwtkit)
[![Known Vulnerabilities](https://snyk.io/test/github/ductran999/jwtkit/badge.svg)](https://snyk.io/test/github/ductran999/jwtkit)
[![License](https://img.shields.io/github/license/DucTran999/jwtkit)](LICENSE)

`jwtkit` is a minimal and extensible utility package for working with JSON Web Tokens (JWT) in Go, built on top of [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt).

✨ _Features_:

- Multiple algorithms (HS256, RS256, ES256, EdDSA, etc.)
- Custom or standard claims
- Signing and parsing support
- Centralized and type-safe error handling

---

## 📦 Installation

```bash
go get github.com/DucTran999/jwtkit
```

## 🚀 Usage

### 🔑 Generate Keys

To generate keys (HMAC secret, RSA, ECDSA, EdDSA):

```bash
task keys
```

### ✍️ Sign & Verify (HMAC - HS256)

```go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/DucTran999/jwtkit"
	"github.com/golang-jwt/jwt/v5"
)

type MyClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func main() {
	cfg := jwtkit.Config{
		Alg:    jwtkit.HS256,
		Secret: []byte("your-secret"),
	}

	signer, err := jwtkit.NewJWT(cfg)
	if err != nil {
		log.Fatal(err)
	}

	claims := MyClaims{
		UserID: "uuid-1234",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	// Sign token
	tokenStr, err := signer.Sign(&claims)
	if err != nil {
		log.Fatal(err)
	}

	// Parse token
	parsed := MyClaims{}
	err = signer.ParseInto(tokenStr, &parsed)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("UserID:", parsed.UserID)
}
```

---

## 🔐 Supported Algorithms

| Algorithm | Name            | Description                              | Status |
| --------- | --------------- | ---------------------------------------- | ------ |
| HS256     | HMAC + SHA-256  | Symmetric key using HMAC with SHA-256    | ✅ Yes |
| HS384     | HMAC + SHA-384  | Symmetric key using HMAC with SHA-384    | ✅ Yes |
| HS512     | HMAC + SHA-512  | Symmetric key using HMAC with SHA-512    | ✅ Yes |
| RS256     | RSA + SHA-256   | RSA public/private key with SHA-256 hash | ✅ Yes |
| RS384     | RSA + SHA-384   | RSA public/private key with SHA-384 hash | ✅ Yes |
| RS512     | RSA + SHA-512   | RSA public/private key with SHA-512 hash | ✅ Yes |
| ES256     | ECDSA + SHA-256 | Elliptic Curve (P-256) with SHA-256 hash | ✅ Yes |
| ES384     | ECDSA + SHA-384 | Elliptic Curve (P-384) with SHA-384 hash | ✅ Yes |
| ES512     | ECDSA + SHA-512 | Elliptic Curve (P-521) with SHA-512 hash | ✅ Yes |
| EdDSA     | Ed25519         | Edwards-curve (Ed25519), modern and fast | ✅ Yes |

---

## 🧪 Testing

Run all tests:

```sh
go test ./...
```

Check test coverage:

```sh
task coverage
```

## 📚 Resources

- [JWT Introduction](https://jwt.io/introduction)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt)

---

## 📜 License

This project is licensed under the [MIT License](./LICENSE).

---

## 🙌 Contributions

Contributions are welcome! Please open an issue or submit a pull request.
