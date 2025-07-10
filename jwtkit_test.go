package jwtkit_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"os"
	"testing"

	"github.com/DucTran999/jwtkit"
	"github.com/DucTran999/jwtkit/test/testdata/testutil"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseInto(t *testing.T) {
	key, err := os.ReadFile("./keys/secret.key")
	require.NoError(t, err)

	type testcase struct {
		name        string
		signFunc    func(t *testing.T) string
		expectedErr error
	}

	// Get default custom claims
	claims := testutil.DefaultMyCustomClaims()
	testcases := []testcase{
		{
			name: "parse successfully",
			signFunc: func(t *testing.T) string {
				t.Helper()
				token, err := testutil.PrepareHMACToken(jwtkit.HS256, claims, key)
				require.NoError(t, err)
				return token
			},
		},
		{
			name: "different algorithm",
			signFunc: func(t *testing.T) string {
				t.Helper()
				token, err := testutil.PrepareHMACToken(jwtkit.HS384, claims, key)
				require.NoError(t, err)
				return token
			},
			expectedErr: jwtkit.ErrParseToken,
		},
		{
			name: "different key singed",
			signFunc: func(t *testing.T) string {
				t.Helper()
				token, err := testutil.PrepareHMACToken(jwtkit.HS256, claims, []byte("different-key"))
				require.NoError(t, err)
				return token
			},
			expectedErr: jwtkit.ErrParseToken,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := jwtkit.Config{
				Alg:    jwtkit.HS256,
				Secret: key,
			}

			signer, err := jwtkit.NewJWT(cfg)
			require.NoError(t, err)

			token := tc.signFunc(t)

			// Test Parse Into
			result := testutil.MyCustomClaims{}
			parsedErr := signer.ParseInto(token, &result)

			// Assert
			if tc.expectedErr == nil {
				require.NoError(t, parsedErr)
				assert.Equal(t, claims.UserID, result.UserID)
			} else {
				require.ErrorIs(t, parsedErr, tc.expectedErr)
			}
		})
	}
}

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
			t.Parallel()
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

func TestRSA(t *testing.T) {
	signKey, verifyKey, err := testutil.LoadRSAKey()
	require.NoError(t, err)

	claims := testutil.DefaultMyCustomClaims()

	type testcase struct {
		name        string
		alg         jwtkit.SigningAlgorithm
		signKey     *rsa.PrivateKey
		verifyKey   *rsa.PublicKey
		expectedErr error
	}

	testcases := []testcase{
		{
			name:        "missing keys",
			alg:         jwtkit.RS256,
			expectedErr: jwtkit.ErrMissingKey,
		},
		{
			name:        "missing verify key",
			alg:         jwtkit.RS256,
			signKey:     signKey,
			expectedErr: jwtkit.ErrMissingKey,
		},
		{
			name:        "missing sign key",
			alg:         jwtkit.RS256,
			verifyKey:   verifyKey,
			expectedErr: jwtkit.ErrMissingKey,
		},
		{
			name:      "rsa256",
			alg:       jwtkit.RS256,
			signKey:   signKey,
			verifyKey: verifyKey,
		},
		{
			name:      "rsa384",
			alg:       jwtkit.RS384,
			signKey:   signKey,
			verifyKey: verifyKey,
		},
		{
			name:      "rsa512",
			alg:       jwtkit.RS512,
			signKey:   signKey,
			verifyKey: verifyKey,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := jwtkit.Config{
				Alg:        tc.alg,
				RSAPrivate: tc.signKey,
				RSAPublic:  tc.verifyKey,
			}

			signer, err := jwtkit.NewJWT(cfg)
			require.ErrorIs(t, err, tc.expectedErr)

			// Verify Sign and ParseInto
			if tc.expectedErr == nil {
				token, err := signer.Sign(claims)
				require.NoError(t, err)

				parsed := testutil.MyCustomClaims{}
				err = signer.ParseInto(token, &parsed)

				require.NoError(t, err)
				assert.Equal(t, claims.UserID, parsed.UserID)
			}
		})
	}
}

func TestECDSA(t *testing.T) {
	claims := testutil.DefaultMyCustomClaims()

	type testcase struct {
		name             string
		alg              jwtkit.SigningAlgorithm
		loadKeyPairs     func(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)
		expectedErr      error
		expectedSignErr  error
		expectedParseErr error
	}

	testcases := []testcase{
		{
			name: "missing keys",
			alg:  jwtkit.ES256,
			loadKeyPairs: func(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
				return nil, nil, nil
			},
			expectedErr: jwtkit.ErrMissingKey,
		},
		{
			name: "missing verify key",
			alg:  jwtkit.ES256,
			loadKeyPairs: func(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
				t.Helper()
				signKey, _, err := testutil.LoadECDSAKeys(
					"ecdsa_256_public.pem",
					"ecdsa_256_private.pem",
				)
				require.NoError(t, err)
				return signKey, nil, nil
			},
			expectedErr: jwtkit.ErrMissingKey,
		},
		{
			name: "missing sign key",
			alg:  jwtkit.ES256,
			loadKeyPairs: func(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
				t.Helper()
				_, verifyKey, err := testutil.LoadECDSAKeys(
					"ecdsa_256_public.pem",
					"ecdsa_256_private.pem",
				)
				require.NoError(t, err)
				return nil, verifyKey, nil
			},
			expectedErr: jwtkit.ErrMissingKey,
		},
		{
			name: "ecdsa256",
			alg:  jwtkit.ES256,
			loadKeyPairs: func(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
				t.Helper()
				signKey, verifyKey, err := testutil.LoadECDSAKeys(
					"ecdsa_256_public.pem",
					"ecdsa_256_private.pem",
				)
				require.NoError(t, err)
				return signKey, verifyKey, nil
			},
		},
		{
			name: "ecdsa256 wrong key ecdsa384",
			alg:  jwtkit.ES256,
			loadKeyPairs: func(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
				t.Helper()
				signKey, verifyKey, err := testutil.LoadECDSAKeys(
					"ecdsa_384_public.pem",
					"ecdsa_384_private.pem",
				)
				require.NoError(t, err)
				return signKey, verifyKey, nil
			},
			expectedSignErr:  jwtkit.ErrSign,
			expectedParseErr: jwtkit.ErrParseToken,
		},
		{
			name: "ecdsa256",
			alg:  jwtkit.ES384,
			loadKeyPairs: func(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
				t.Helper()
				signKey, verifyKey, err := testutil.LoadECDSAKeys(
					"ecdsa_384_public.pem",
					"ecdsa_384_private.pem",
				)
				require.NoError(t, err)
				return signKey, verifyKey, nil
			},
		},
		{
			name: "ecdsa512",
			alg:  jwtkit.ES512,
			loadKeyPairs: func(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
				t.Helper()
				signKey, verifyKey, err := testutil.LoadECDSAKeys(
					"ecdsa_512_public.pem",
					"ecdsa_512_private.pem",
				)
				require.NoError(t, err)
				return signKey, verifyKey, nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel()
			signKey, verifyKey, err := tc.loadKeyPairs(t)
			require.NoError(t, err)

			cfg := jwtkit.Config{
				Alg:       tc.alg,
				ESPrivate: signKey,
				ESPublic:  verifyKey,
			}

			signer, err := jwtkit.NewJWT(cfg)
			require.ErrorIs(t, err, tc.expectedErr)

			// Verify Sign and ParseInto
			if tc.expectedErr == nil {
				token, err := signer.Sign(claims)
				require.ErrorIs(t, err, tc.expectedSignErr)

				parsed := testutil.MyCustomClaims{}
				err = signer.ParseInto(token, &parsed)
				require.ErrorIs(t, err, tc.expectedParseErr)

				if tc.expectedParseErr == nil {
					assert.Equal(t, claims.UserID, parsed.UserID)
				}
			}
		})
	}
}
