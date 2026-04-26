package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/authn"
	"github.com/charmbracelet/log"
	"github.com/golang-jwt/jwt/v5"
)

// jwtSecret is the HMAC signing key. In production, load from secret.
var jwtSecret = []byte("example-secret")

// Identity represents an authenticated user extracted from a JWT.
type Identity struct {
	Subject string
	Roles   []string
}

// GetIdentity extracts the authenticated identity from the request context.
// It reads the value set by the authn middleware via [authn.SetInfo].
func GetIdentity(ctx context.Context) any {
	return authn.GetInfo(ctx)
}

// ExtractSubjects returns the Casbin subject for an identity.
// Casbin resolves roles via the g (grouping) policy rules.
func ExtractSubjects(identity any) []string {
	return []string{identity.(*Identity).Subject}
}

// Claims is the JWT claims structure.
type Claims struct {
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

func issueToken(subject string, roles []string) (string, error) {
	claims := &Claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
}

func validateToken(tokenString string) (*Identity, error) {
	token, err := jwt.ParseWithClaims(
		tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
			return jwtSecret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}
	return &Identity{Subject: claims.Subject, Roles: claims.Roles}, nil
}

type tokenRequest struct {
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
}

type tokenResponse struct {
	Token string `json:"token"`
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	token, err := issueToken(req.Subject, req.Roles)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	log.Info("token issued", "subject", req.Subject, "roles", req.Roles)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse{Token: token})
}
