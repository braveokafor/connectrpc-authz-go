package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"github.com/charmbracelet/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	authz "github.com/braveokafor/connectrpc-authz-go"
	"github.com/braveokafor/connectrpc-authz-go/examples/fullstack/gen/document/v1/documentv1connect"
)

// publicPaths lists path prefixes that do not require authentication.
var publicPaths = []string{"/token", "/grpc.reflection."}

func main() {
	// --- Casbin enforcer ---
	enforcer, err := authz.NewCasbinEnforcerFromFiles("model.conf", "policy.csv", ExtractSubjects)
	if err != nil {
		log.Fatal("failed to create casbin enforcer", "err", err)
	}

	// --- Decision handler ---
	onDecision := func(ctx context.Context, d authz.Decision) {
		if d.Allowed {
			id := d.Identity.(*Identity)
			log.Info("authorized", "subject", id.Subject, "procedure", d.Procedure)
		} else {
			subject := "<none>"
			if d.Identity != nil {
				subject = d.Identity.(*Identity).Subject
			}
			log.Warn("denied", "subject", subject, "procedure", d.Procedure, "err", d.Error)
		}
	}

	// --- authz interceptor ---
	interceptor, err := authz.NewInterceptor(GetIdentity, enforcer, authz.WithDecisionHandler(onDecision))
	if err != nil {
		log.Fatal("failed to create authz interceptor", "err", err)
	}

	// --- authn middleware ---
	// Returns nil, nil for public paths (no auth required, no identity).
	// For all other paths, validates the JWT bearer token.
	authenticate := authn.AuthFunc(func(ctx context.Context, req *http.Request) (any, error) {
		for _, prefix := range publicPaths {
			if strings.HasPrefix(req.URL.Path, prefix) {
				return nil, nil
			}
		}
		token, ok := authn.BearerToken(req)
		if !ok {
			return nil, authn.Errorf("missing bearer token")
		}
		identity, err := validateToken(token)
		if err != nil {
			return nil, authn.Errorf("invalid token: %v", err)
		}
		log.Info("authenticated", "subject", identity.Subject)
		return identity, nil
	})
	authnMiddleware := authn.NewMiddleware(authenticate)

	// --- HTTP mux ---
	mux := http.NewServeMux()

	// Token issuance endpoint (public)
	mux.HandleFunc("/token", tokenHandler)

	// Document service (protected by authz interceptor)
	path, handler := documentv1connect.NewDocumentServiceHandler(
		NewDocumentServer(),
		connect.WithInterceptors(interceptor),
	)
	mux.Handle(path, handler)

	// gRPC reflection for grpcurl service discovery
	reflector := grpcreflect.NewStaticReflector(documentv1connect.DocumentServiceName)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	// authn middleware wraps the entire mux, h2c enables HTTP/2 cleartext for gRPC
	addr := ":8080"
	srv := &http.Server{
		Addr:    addr,
		Handler: h2c.NewHandler(authnMiddleware.Wrap(mux), &http2.Server{}),
	}

	go func() {
		log.Info("server started", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("server failed", "err", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("forced shutdown", "err", err)
	}
	log.Info("server stopped")
}
