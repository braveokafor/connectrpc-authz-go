authz
=====
[![Build](https://github.com/braveokafor/connectrpc-authz-go/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/braveokafor/connectrpc-authz-go/actions/workflows/ci.yaml)
[![GoDoc](https://pkg.go.dev/badge/github.com/braveokafor/connectrpc-authz-go.svg)](https://pkg.go.dev/github.com/braveokafor/connectrpc-authz-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/braveokafor/connectrpc-authz-go/blob/main/LICENSE)

`github.com/braveokafor/connectrpc-authz-go` provides authorisation interceptors for [Connect](https://connectrpc.com/). The identity comes from any authentication layer, for example [connectrpc.com/authn](https://github.com/connectrpc/authn-go).

The core package defines `Request`, `Enforcer`, and the interceptor, and depends only on `connectrpc.com/connect`. The [`casbin`](casbin/) subpackage implements `Enforcer` with [Casbin](https://casbin.org/).

The interceptor supports unary and streaming RPCs on the Connect, gRPC, and gRPC-Web protocols.

## Installation

```bash
go get github.com/braveokafor/connectrpc-authz-go
```

## Example

```go
package main

import (
	"context"
	"log"
	"net/http"
	"slices"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
	authz "github.com/braveokafor/connectrpc-authz-go"
	"github.com/braveokafor/connectrpc-authz-go/examples/bookstore/gen/bookstore/v1/bookstorev1connect"
)

type Identity struct {
	Subject string
	Roles   []string
}

func main() {
	// Deny by default. Allow what you recognise.
	checkAuth := authz.EnforcerFunc(func(ctx context.Context, r *authz.Request) error {
		id, ok := r.Identity.(*Identity)
		if !ok {
			return authz.ErrorUnauthenticated("authentication required")
		}
		switch r.Spec.Procedure {
		case "/bookstore.v1.BookstoreService/DeleteBook":
			if !slices.Contains(id.Roles, "admin") {
				return authz.ErrorPermissionDenied("requires admin role")
			}
			return nil
		case "/bookstore.v1.BookstoreService/GetBook":
			return nil
		}
		return authz.ErrorPermissionDenied("permission denied")
	})

	interceptor, err := authz.NewInterceptor(checkAuth,
		authz.WithIdentityFunc(authn.GetInfo), // bridge from authn middleware
	)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle(bookstorev1connect.NewBookstoreServiceHandler(
		NewBookstoreServer(),
		connect.WithInterceptors(interceptor),
	))

	log.Println("Server starting on :8080")
	http.ListenAndServe("localhost:8080", authn.NewMiddleware(authenticate).Wrap(mux))
}
```

## The Request

```go
type Request struct {
	Identity any          // authenticated identity, or nil for an unauthenticated caller
	Spec     connect.Spec // procedure, schema, stream type
	Peer     connect.Peer
	Header   http.Header
	Message  any          // request message, or nil for streaming RPCs
}
```

## The casbin implementation

```go
import (
	_ "embed"

	authzcasbin "github.com/braveokafor/connectrpc-authz-go/casbin"
)

//go:embed policies/model.conf
var model string

//go:embed policies/policy.csv
var policy string

enforcer, err := authzcasbin.NewFromString(model, policy,
	func(r *authz.Request) []string {
		id, ok := r.Identity.(*Identity)
		if !ok {
			return nil
		}
		return []string{id.Subject}
	})

interceptor, err := authz.NewInterceptor(enforcer, authz.WithIdentityFunc(authn.GetInfo))
```

Constructors:

- `New(engine, subjects, opts...)` wraps an existing `casbin.IEnforcer`.
- `NewFromString(modelText, policyText, subjects, opts...)` builds a `SyncedEnforcer` from model and policy text.

The library maps the request to Casbin as `(subject, object, action)`:

- `SubjectsFunc` derives the subjects. Keep a role lookup that needs I/O in the authentication layer.
- Objects default to `{r.Spec.Procedure}`. `WithObjects` builds other objects, and can use the message.
- The action defaults to `"execute"`. `WithAction` changes it.

Semantics:

- The enforcer allows a request when, for every object, at least one subject has access.
- An allow from one subject overrides a deny row that names another. Give an absolute deny rule the subject `*`.
- The enforcer denies an identified caller that has no subjects. It returns `CodeUnauthenticated` for a nil identity with no subjects. It denies a request that has no objects. It denies a request when the engine returns an error.

## Write your own Enforcer

For a policy outside `(subject, object, action)`, implement the one method, for example multi-tenancy with Casbin RBAC and domains:

```go
type tenantEnforcer struct{ e *casbin.SyncedEnforcer }

func (t *tenantEnforcer) Enforce(ctx context.Context, r *authz.Request) error {
	id, ok := r.Identity.(*Identity)
	if !ok {
		return authz.ErrorUnauthenticated("authentication required")
	}
	tenant := r.Header.Get("Tenant-Id")
	if m, ok := r.Message.(interface{ GetTenantId() string }); ok && m.GetTenantId() != "" {
		tenant = m.GetTenantId()
	}
	if tenant == "" {
		return authz.ErrorPermissionDenied("missing tenant")
	}
	ok, err := t.e.Enforce(id.Subject, tenant, r.Spec.Procedure, "execute")
	if err != nil {
		return err // uncoded, so the wire gets a generic denial and the log gets the detail
	}
	if !ok {
		return authz.ErrorPermissionDenied("permission denied")
	}
	return nil
}
```

## The decision handler

Use the decision handler for logging, metrics, and audit trails:

```go
onDecision := func(ctx context.Context, d authz.Decision) {
	log.Printf("authz procedure=%s allowed=%t duration=%s err=%v",
		d.Request.Spec.Procedure, d.Allowed, d.Duration, d.Error)
}

interceptor, err := authz.NewInterceptor(enforcer,
	authz.WithIdentityFunc(authn.GetInfo),
	authz.WithDecisionHandler(onDecision),
)
```

`Duration` is the time in the `Enforcer`. `Error` is the original error before wire sanitisation. The handler runs one time for each decision, allow or deny. The call is synchronous. `Request.Identity` and `Request.Message` may contain personal data or secrets

## Full example

See [examples/bookstore](examples/bookstore) for a runnable Casbin example.
