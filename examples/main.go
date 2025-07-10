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

	val, ok := (*parsed)["user_id"]
	if ok {
		fmt.Println("UserID:", val)
	} else {
		fmt.Println("UserID is not found")
	}
}
