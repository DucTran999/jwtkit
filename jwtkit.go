package jwtkit

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type jwtImpl struct {
	method    jwt.SigningMethod
	signKey   any
	verifyKey any
}

func NewJWT(cfg Config) (JWT, error) {
	signMethod, err := cfg.Alg.ToJWTMethod()
	if err != nil {
		return nil, err
	}

	signKey, verifyKey, err := cfg.GetKeyPairs(signMethod)
	if err != nil {
		return nil, err
	}

	j := &jwtImpl{
		method:    signMethod,
		signKey:   signKey,
		verifyKey: verifyKey,
	}
	return j, nil
}

func (j *jwtImpl) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(j.method, claims)
	return token.SignedString(j.signKey)
}

func (j *jwtImpl) Parse(tokenStr string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		// Validate that the token's algorithm matches our signer's algorithm
		if t.Method.Alg() != j.method.Alg() {
			return nil, ErrAlgorithmNotMatch
		}
		return j.verifyKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("jwtkit: failed to parse token: %w", err)
	}

	if token == nil || !token.Valid {
		return nil, ErrInvalidTokenSignature
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidTokenClaimType
	}

	return &claims, nil
}
