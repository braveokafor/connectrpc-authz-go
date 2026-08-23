package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/authn"
	"github.com/golang-jwt/jwt/v5"
)

var devSecret = []byte("dev-secret")

var publicPrefixes = []string{"/grpc.reflection."}

type Identity struct {
	Subject string
}

func authenticate(_ context.Context, req *http.Request) (any, error) {
	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(req.URL.Path, prefix) {
			return nil, nil
		}
	}
	token, ok := authn.BearerToken(req)
	if !ok {
		return nil, authn.Errorf("missing bearer token")
	}
	parsed, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(*jwt.Token) (any, error) {
		return devSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, authn.Errorf("invalid token: %v", err)
	}
	return &Identity{Subject: parsed.Claims.(*jwt.RegisteredClaims).Subject}, nil
}

func signToken(subject string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.RegisteredClaims{
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}).SignedString(devSecret)
}

func getSubject(ctx context.Context) string {
	if id, ok := authn.GetInfo(ctx).(*Identity); ok && id != nil {
		return id.Subject
	}
	return ""
}
