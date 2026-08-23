package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	authz "github.com/braveokafor/connectrpc-authz-go"
	"github.com/braveokafor/connectrpc-authz-go/examples/bookstore/gen/bookstore/v1/bookstorev1connect"
)

func main() {
	token := flag.String("token", "", "print a signed token for this subject and exit")
	flag.Parse()

	if *token != "" {
		signed, err := signToken(*token)
		if err != nil {
			slog.Error("sign token", "err", err)
			os.Exit(1)
		}
		fmt.Println(signed)
		return
	}

	enforcer, err := newEnforcer()
	if err != nil {
		slog.Error("build enforcer", "err", err)
		os.Exit(1)
	}

	onDecision := func(_ context.Context, d authz.Decision) {
		subject := "<none>"
		if id, ok := d.Request.Identity.(*Identity); ok && id != nil {
			subject = id.Subject
		}
		if d.Allowed {
			slog.Info("authorised", "subject", subject, "procedure", d.Request.Spec.Procedure)
		} else {
			slog.Warn("denied", "subject", subject, "procedure", d.Request.Spec.Procedure, "err", d.Error)
		}
	}

	interceptor, err := authz.NewInterceptor(enforcer,
		authz.WithIdentityFunc(authn.GetInfo),
		authz.WithDecisionHandler(onDecision),
	)
	if err != nil {
		slog.Error("build interceptor", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	path, handler := bookstorev1connect.NewBookstoreServiceHandler(
		NewBookstoreServer(),
		connect.WithInterceptors(interceptor),
	)
	mux.Handle(path, handler)

	reflector := grpcreflect.NewStaticReflector(bookstorev1connect.BookstoreServiceName)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	addr := ":8080"
	srv := &http.Server{
		Addr:    addr,
		Handler: h2c.NewHandler(authn.NewMiddleware(authenticate).Wrap(mux), &http2.Server{}),
	}

	go func() {
		slog.Info("listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("serve", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown", "err", err)
	}
}
