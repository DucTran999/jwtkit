package jwtkit_test

import (
	"os"
	"testing"
	"time"

	"github.com/DucTran999/jwtkit"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHMAC(t *testing.T) {
	key, err := os.ReadFile("./keys/secret.key")
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"id":  1,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	type testCase struct {
		name        string
		alg         jwtkit.SigningAlgorithm
		secret      []byte
		inputClaims jwt.MapClaims
		expectedErr error
	}

	testcases := []testCase{
		{"invalid algorithm", "AES", key, claims, jwtkit.ErrInvalidAlgorithm},
		{"missing key", jwtkit.HS256, []byte{}, claims, jwtkit.ErrMissingKey},
		{"algorithm HS256", jwtkit.HS256, key, claims, nil},
		{"algorithm HS384", jwtkit.HS384, key, claims, nil},
		{"algorithm HS512", jwtkit.HS512, key, claims, nil},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := jwtkit.Config{
				Alg:    tc.alg,
				Secret: tc.secret,
			}

			signer, err := jwtkit.NewJWT(cfg)
			require.ErrorIs(t, err, tc.expectedErr)

			if tc.expectedErr == nil {
				// Test Sign
				tokenStr, err := signer.Sign(claims)
				require.NoError(t, err)

				// Test Parse
				result, err := signer.Parse(tokenStr)

				require.NoError(t, err)
				require.NotNil(t, result)
				assert.InEpsilon(t, float64(1), (*result)["id"], 1)
			}
		})
	}
}
