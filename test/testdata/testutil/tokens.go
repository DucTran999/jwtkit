package testutil

import (
	"github.com/DucTran999/jwtkit"
	"github.com/golang-jwt/jwt/v5"
)

func PrepareHMACToken(alg jwtkit.SigningAlgorithm, claims jwt.Claims, signKey []byte) (string, error) {
	cfg := jwtkit.Config{
		Alg:    alg,
		Secret: signKey,
	}

	signer, err := jwtkit.NewJWT(cfg)
	if err != nil {
		return "", err
	}

	token, err := signer.Sign(claims)
	if err != nil {
		return "", nil
	}

	return token, nil
}
