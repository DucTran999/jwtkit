package jwtkit_test

import (
	"os"
	"testing"

	"github.com/DucTran999/jwtkit"
	"github.com/DucTran999/jwtkit/test/testdata/testutil"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGotError(t *testing.T) {
	type testCase struct {
		name        string
		setupToken  func(t *testing.T) string
		expectedErr error
	}

	key, err := os.ReadFile("./keys/secret.key")
	require.NoError(t, err)

	testcases := []testCase{
		{
			name:        "empty token",
			setupToken:  func(t *testing.T) string { return "" },
			expectedErr: jwtkit.ErrParseToken,
		},
		{
			name:        "invalid token format",
			setupToken:  func(t *testing.T) string { return "abc.xyx.213" },
			expectedErr: jwtkit.ErrParseToken,
		},
		{
			name: "different signing method",
			setupToken: func(t *testing.T) string {
				t.Helper()
				token, err := testutil.PrepareHMACToken(jwtkit.HS384, testutil.DefaultClaims(), key)
				require.NoError(t, err)
				return token
			},
			expectedErr: jwtkit.ErrParseToken,
		},
		{
			name: "different key sign",
			setupToken: func(t *testing.T) string {
				t.Helper()
				token, err := testutil.PrepareHMACToken(jwtkit.HS256, testutil.DefaultClaims(), []byte("fake-key"))
				require.NoError(t, err)
				return token
			},
			expectedErr: jwtkit.ErrParseToken,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel()
			inputToken := tc.setupToken(t)

			cfg := jwtkit.Config{
				Alg:    jwtkit.HS256,
				Secret: key,
			}

			signer, err := jwtkit.NewJWT(cfg)
			require.NoError(t, err)

			_, parseErr := signer.Parse(inputToken)
			assert.ErrorIs(t, parseErr, tc.expectedErr)
		})
	}
}

func TestHMAC(t *testing.T) {
	key, err := os.ReadFile("./keys/secret.key")
	require.NoError(t, err)

	claims := testutil.DefaultClaims()

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
				assert.Equal(t, "uuid-1", (*result)["id"])
			}
		})
	}
}
