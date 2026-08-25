package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	// UserContextKey is the context key for the parsed jwt.Token.
	UserContextKey contextKey = "user"
	// ClaimsContextKey is the context key for the parsed claims.
	ClaimsContextKey contextKey = "claims"
)

var (
	ErrMissingToken      = errors.New("missing or malformed jwt token")
	ErrInvalidAlgorithm  = errors.New("invalid or disallowed signing algorithm")
	ErrAlgorithmNone     = errors.New("signing algorithm 'none' is not allowed")
	ErrInvalidToken      = errors.New("invalid or expired jwt token")
	ErrMissingSigningKey = errors.New("missing signing key configuration")
)

// Config defines the configuration options for the JWT authentication middleware.
type Config struct {
	// SigningKey is the secret (HMAC) or public key (RSA/ECDSA) used to verify token signatures.
	SigningKey any

	// KeyFunc allows dynamic key resolution based on token headers/claims.
	KeyFunc jwt.Keyfunc

	// AllowedAlgorithms is an allowlist of permitted signing algorithm names (e.g., ["HS256"], ["RS256"]).
	AllowedAlgorithms []string

	// ExpectedSigningMethod enforces a specific signing algorithm (e.g., "HS256", "RS256", "ES256").
	ExpectedSigningMethod string

	// ClaimsFactory optionally creates a custom jwt.Claims instance for token parsing.
	ClaimsFactory func() jwt.Claims

	// ContextKey specifies the context key under which parsed claims are stored. Defaults to ClaimsContextKey.
	ContextKey any

	// ErrorHandler handles authentication errors. If nil, default 401 Unauthorized JSON response is written.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
}

// JWTMiddleware validates JWT tokens on incoming HTTP requests.
type JWTMiddleware struct {
	config Config
}

// New creates a new JWTMiddleware instance with the provided configuration.
func New(config Config) *JWTMiddleware {
	if config.ContextKey == nil {
		config.ContextKey = ClaimsContextKey
	}
	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultErrorHandler
	}
	if len(config.AllowedAlgorithms) == 0 && config.ExpectedSigningMethod != "" {
		config.AllowedAlgorithms = []string{config.ExpectedSigningMethod}
	}
	return &JWTMiddleware{config: config}
}

// Handler wraps an http.Handler with JWT authentication.
func (m *JWTMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := extractTokenFromHeader(r)
		if err != nil {
			m.config.ErrorHandler(w, r, err)
			return
		}

		token, err := m.parseAndValidateToken(tokenStr)
		if err != nil {
			m.config.ErrorHandler(w, r, err)
			return
		}

		ctx := context.WithValue(r.Context(), m.config.ContextKey, token.Claims)
		ctx = context.WithValue(ctx, UserContextKey, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *JWTMiddleware) parseAndValidateToken(tokenString string) (*jwt.Token, error) {
	keyFunc := func(token *jwt.Token) (any, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok || alg == "" || strings.EqualFold(alg, "none") {
			return nil, ErrAlgorithmNone
		}

		if token.Method == jwt.SigningMethodNone {
			return nil, ErrAlgorithmNone
		}

		// Validate against configured ExpectedSigningMethod
		if m.config.ExpectedSigningMethod != "" && token.Method.Alg() != m.config.ExpectedSigningMethod {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidAlgorithm, m.config.ExpectedSigningMethod, token.Method.Alg())
		}

		// Validate against configured AllowedAlgorithms list
		if len(m.config.AllowedAlgorithms) > 0 {
			allowed := false
			for _, allowedAlg := range m.config.AllowedAlgorithms {
				if token.Method.Alg() == allowedAlg {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, fmt.Errorf("%w: algorithm %s is not permitted", ErrInvalidAlgorithm, token.Method.Alg())
			}
		}

		if m.config.KeyFunc != nil {
			return m.config.KeyFunc(token)
		}

		if m.config.SigningKey == nil {
			return nil, ErrMissingSigningKey
		}

		return m.config.SigningKey, nil
	}

	var parserOpts []jwt.ParserOption
	if len(m.config.AllowedAlgorithms) > 0 {
		parserOpts = append(parserOpts, jwt.WithValidMethods(m.config.AllowedAlgorithms))
	}

	var claims jwt.Claims
	if m.config.ClaimsFactory != nil {
		claims = m.config.ClaimsFactory()
	} else {
		claims = jwt.MapClaims{}
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc, parserOpts...)
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	return token, nil
}

func extractTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrMissingToken
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", ErrMissingToken
	}

	return strings.TrimSpace(parts[1]), nil
}

func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
}
