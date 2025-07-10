# 🔐 jwtkit

[![Go Report Card](https://goreportcard.com/badge/github.com/DucTran999/jwtkit)](https://goreportcard.com/report/github.com/DucTran999/jwtkit)
[![Go](https://img.shields.io/badge/Go-1.23-blue?logo=go)](https://golang.org)
[![CI](https://github.com/DucTran999/jwtkit/actions/workflows/ci.yml/badge.svg)](https://github.com/DucTran999/jwtkit/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/DucTran999/jwtkit/branch/master/graph/badge.svg)](https://codecov.io/gh/DucTran999/jwtkit)
[![Known Vulnerabilities](https://snyk.io/test/github/ductran999/jwtkit/badge.svg)](https://snyk.io/test/github/ductran999/jwtkit)
[![License](https://img.shields.io/github/license/DucTran999/jwtkit)](LICENSE)

`jwtkit` is a minimal and extensible utility package for working with JSON Web Tokens (JWT) in Go, built on top of [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt).

It supports:

- Multiple algorithms (HS256, RS256, etc.)
- Custom claims or standard claims
- Signing and parsing
- Centralized error handling

---

## 📦 Installation

```bash
go get github.com/DucTran999/jwtkit
```

## 🚀 Usage

Basic Sign & Parse with HMAC (HS256)

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
	parsed, err := signer.Parse(tokenStr)
	if err != nil {
		log.Fatal(err)
	}

	val, _ := (*parsed)["user_id"]

	fmt.Println("UserID:", val)
}
```

---

## 🔐 Supported Algorithms

| Algorithm | Status        |
| --------- | ------------- |
| HS256     | ✅ Yes        |
| HS384     | ✅ Yes        |
| HS512     | ✅ Yes        |
| RS256     | 🛠 In progress |
| ES256     | 🛠 In progress |

---

## 📜 License

This project is licensed under the [MIT License](./LICENSE).

---

## 🙌 Contributions

Contributions are welcome! Please open an issue or submit a pull request.
