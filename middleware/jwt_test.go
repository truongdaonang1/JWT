package middleware_test

import (
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"truongdaonang1/JWT/middleware"
)

func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}

func TestValidHMACRequest(t *testing.T) {
	secret := []byte("super-secret-key-12345")
	mw := middleware.New(middleware.Config{
		SigningKey:            secret,
		ExpectedSigningMethod: "HS256",
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user123"})
	tokenStr, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	mw.Handler(dummyHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestRejectAlgorithmNone(t *testing.T) {
	secret := []byte("super-secret-key-12345")
	mw := middleware.New(middleware.Config{
		SigningKey:            secret,
		ExpectedSigningMethod: "HS256",
	})

	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "user123"})
	tokenStr, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to create none token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	mw.Handler(dummyHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for none algorithm, got %d", rec.Code)
	}
}

func TestAlgorithmMismatchAttackHMACForRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(cryptoRand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mw := middleware.New(middleware.Config{
		SigningKey:            &rsaKey.PublicKey,
		ExpectedSigningMethod: "RS256",
	})

	// Attacker signs using HS256 with dummy key
	hmacToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "attacker"})
	hmacTokenStr, err := hmacToken.SignedString([]byte("attacker-secret"))
	if err != nil {
		t.Fatalf("failed to sign HMAC token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+hmacTokenStr)
	rec := httptest.NewRecorder()

	mw.Handler(dummyHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for algorithm mismatch, got %d", rec.Code)
	}
}

func TestMissingAuthorizationHeader(t *testing.T) {
	mw := middleware.New(middleware.Config{
		SigningKey:            []byte("secret"),
		ExpectedSigningMethod: "HS256",
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	mw.Handler(dummyHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for missing header, got %d", rec.Code)
	}
}
