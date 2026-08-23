// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

package casbin_test

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	authz "github.com/braveokafor/connectrpc-authz-go"
	casbin "github.com/braveokafor/connectrpc-authz-go/casbin"
)

// ExampleNewFromString builds the enforcer from embedded model and policy text.
func ExampleNewFromString() {
	const (
		model = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
		policy = `
p, viewer, /bookstore.v1.BookstoreService/GetBook, execute
p, admin, /bookstore.v1.BookstoreService/DeleteBook, execute
`
	)

	type user struct{ Roles []string }

	enforcer, err := casbin.NewFromString(model, policy, func(r *authz.Request) []string {
		u, ok := r.Identity.(*user)
		if !ok {
			return nil
		}
		return u.Roles
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	ctx := context.Background()
	viewer := &user{Roles: []string{"viewer"}}
	get := enforcer.Enforce(
		ctx,
		&authz.Request{
			Identity: viewer,
			Spec:     connect.Spec{Procedure: "/bookstore.v1.BookstoreService/GetBook"},
		},
	)
	del := enforcer.Enforce(
		ctx,
		&authz.Request{
			Identity: viewer,
			Spec:     connect.Spec{Procedure: "/bookstore.v1.BookstoreService/DeleteBook"},
		},
	)
	fmt.Printf("viewer GetBook: %v\n", get == nil)
	fmt.Printf("viewer DeleteBook: %v\n", del == nil)

	// Output:
	// viewer GetBook: true
	// viewer DeleteBook: false
}
