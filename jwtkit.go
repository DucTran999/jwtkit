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
	if err != nil || token == nil || !token.Valid {
		return nil, fmt.Errorf("%w: %s", ErrParseToken, err.Error())
	}

	// The jwt.Parse internally always use MapClaims so this will always true
	claims, _ := token.Claims.(jwt.MapClaims)
	return &claims, nil
}

func (j *jwtImpl) ParseInto(tokenStr string, dest jwt.Claims) error {
	token, err := jwt.ParseWithClaims(tokenStr, dest, func(t *jwt.Token) (any, error) {
		// Validate that the token's algorithm matches our signer's algorithm
		if t.Method.Alg() != j.method.Alg() {
			return nil, ErrAlgorithmNotMatch
		}
		return j.verifyKey, nil
	})

	if err != nil || token == nil || !token.Valid {
		return fmt.Errorf("%w: %s", ErrParseToken, err.Error())
	}

	return nil
}
