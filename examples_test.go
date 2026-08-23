// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

package authz_test

import (
	"context"
	"fmt"
	"log"
	"slices"

	"connectrpc.com/connect"
	authz "github.com/braveokafor/connectrpc-authz-go"
)

type exampleUser struct {
	Email string
	Roles []string
}

type exampleUserKey struct{}

// ExampleNewInterceptor demonstrates the core wiring: an EnforcerFunc, the identity bridge, and a decision log.
func ExampleNewInterceptor() {
	enforce := authz.EnforcerFunc(func(ctx context.Context, r *authz.Request) error {
		user, ok := r.Identity.(*exampleUser)
		if !ok {
			return authz.ErrorUnauthenticated("authentication required")
		}
		if r.Spec.Procedure == "/bookstore.v1.BookstoreService/DeleteBook" &&
			!slices.Contains(user.Roles, "admin") {
			return authz.ErrorPermissionDenied("requires admin role")
		}
		return nil
	})

	interceptor, err := authz.NewInterceptor(enforce,
		authz.WithIdentityFunc(func(ctx context.Context) any {
			return ctx.Value(exampleUserKey{})
		}),
		authz.WithDecisionHandler(func(ctx context.Context, d authz.Decision) {
			log.Printf("authz %s allowed=%t", d.Request.Spec.Procedure, d.Allowed)
		}),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = interceptor // Use with connect.WithInterceptors(interceptor).

	admin := &exampleUser{Email: "admin@example.com", Roles: []string{"admin"}}
	dev := &exampleUser{Email: "dev@example.com", Roles: []string{"dev"}}
	for _, r := range []*authz.Request{
		{Identity: admin, Spec: connect.Spec{Procedure: "/bookstore.v1.BookstoreService/DeleteBook"}},
		{Identity: dev, Spec: connect.Spec{Procedure: "/bookstore.v1.BookstoreService/DeleteBook"}},
		{Identity: dev, Spec: connect.Spec{Procedure: "/bookstore.v1.BookstoreService/GetBook"}},
	} {
		err := enforce.Enforce(context.Background(), r)
		fmt.Printf("%s %s: %v\n", r.Identity.(*exampleUser).Email, r.Spec.Procedure, err == nil)
	}

	// Output:
	// admin@example.com /bookstore.v1.BookstoreService/DeleteBook: true
	// dev@example.com /bookstore.v1.BookstoreService/DeleteBook: false
	// dev@example.com /bookstore.v1.BookstoreService/GetBook: true
}
