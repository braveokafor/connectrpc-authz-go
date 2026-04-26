authz
=====
[![Build](https://github.com/braveokafor/connectrpc-authz-go/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/braveokafor/connectrpc-authz-go/actions/workflows/ci.yaml)
[![Report Card](https://goreportcard.com/badge/github.com/braveokafor/connectrpc-authz-go)](https://goreportcard.com/report/github.com/braveokafor/connectrpc-authz-go)
[![GoDoc](https://pkg.go.dev/badge/github.com/braveokafor/connectrpc-authz-go.svg)](https://pkg.go.dev/github.com/braveokafor/connectrpc-authz-go)

`github.com/braveokafor/connectrpc-authz-go` provides authorization interceptors for [Connect](https://connectrpc.com/). It works with any authentication system (including [connectrpc.com/authn](https://connectrpc.com/authn), custom context-based auth, or external providers), and supports both custom authorization logic and policy-based authorization with [Casbin](https://casbin.org/).

Interceptors built with `authz` cover both unary and streaming RPCs made with the Connect, gRPC, and gRPC-Web protocols.

## Installation

```bash
go get github.com/braveokafor/connectrpc-authz-go
```

## A small example

Curious what all this looks like in practice? Here's a simple role-based authorization check:

```go
package main

import (
	"context"
	"log"
	"net/http"
	"slices"

	"connectrpc.com/connect"
	authz "github.com/braveokafor/connectrpc-authz-go"
	"example.com/gen/greet/v1/greetv1connect"
)

type User struct {
	Email string
	Roles []string
}

func main() {
	// Custom authorization logic as an EnforcerFunc
	checkAuth := authz.EnforcerFunc(func(ctx context.Context, identity any, procedure string) error {
		user, ok := identity.(*User)
		if !ok {
			return authz.Errorf("invalid identity type")
		}

		// Require admin role for admin procedures
		if procedure == "/admin.v1.AdminService/DeleteUser" {
			if !slices.Contains(user.Roles, "admin") {
				return authz.Errorf("requires admin role")
			}
		}
		return nil
	})

	getIdentity := func(ctx context.Context) any {
		// Extract identity from context (set by your authentication middleware)
		user, _ := ctx.Value("user").(*User)
		return user
	}


	// Create authorization interceptor
	interceptor, err := authz.NewInterceptor(getIdentity, checkAuth)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	// Register service with interceptor
	mux.Handle(greetv1connect.NewGreetServiceHandler(
		&GreetService{},
		connect.WithInterceptors(interceptor),
	))

	log.Println("Server starting on :8080")
	http.ListenAndServe("localhost:8080", mux)
}
```

The interceptor extracts the identity using `getIdentity`, then calls your `Enforcer` to check permissions. If authorization fails, the RPC returns `CodePermissionDenied`. If no identity is found, it returns `CodeUnauthenticated`.

## Features

- **Decoupled Design**: Works with any authentication system - no dependencies on [authn-go](https://github.com/connectrpc/authn-go) or specific auth libraries
- **Flexible Authorization**: Bring your own authz logic via `EnforcerFunc`, or use built-in Casbin integration
- **Casbin Support**: Optional Casbin adapter with file-based, adapter-based, and programmatic configuration
- **Decision Hooks**: Optional `DecisionFunc` callback for logging, metrics, audit trails, and webhooks
- **Unary and Streaming**: Supports both unary and streaming RPCs
- **ConnectRPC Native**: Implements `connect.Interceptor` interface following production patterns

## Decision Handler

React to authorization outcomes - logging, metrics, audit trails, Slack webhooks, Kafka events:

```go
onDecision := func(ctx context.Context, d authz.Decision) {
	if d.Allowed {
		log.Printf("ALLOW subject=%v procedure=%s", d.Identity, d.Procedure)
	} else {
		log.Printf("DENY  subject=%v procedure=%s err=%v", d.Identity, d.Procedure, d.Error)
	}
}

interceptor, err := authz.NewInterceptor(getIdentity, enforcer,
	authz.WithDecisionHandler(onDecision),
)
```

## Casbin Integration

For policy-based authorization, use the built-in Casbin enforcer:

```go
// Extract subject from identity for Casbin
extractSubject := func(identity any) []string {
	user, ok := identity.(*User)
	if !ok {
		return nil
	}
	return []string{user.Email}
}

// Create Casbin enforcer from policy files
enforcer, err := authz.NewCasbinEnforcerFromFiles(
	"model.conf",
	"policy.csv",
	extractSubject,
)
if err != nil {
	log.Fatal(err)
}

// Create interceptor - CasbinEnforcer implements Enforcer
interceptor, err := authz.NewInterceptor(getIdentity, enforcer)
```

Three constructors available:
- `NewCasbinEnforcerFromFiles(modelPath, policyPath, subjectExtractor)` - Casbin file paths
- `NewCasbinEnforcerFromAdapter(model, adapter, subjectExtractor)` - Database/Redis/custom adapters
- `NewCasbinEnforcerFromString(modelText, policyText, subjectExtractor)` - Mostly for testing

### Custom action resolver

By default, the Casbin action is `"execute"`. Use `WithActionResolver` for fine-grained actions:

```go
enforcer, err := authz.NewCasbinEnforcerFromFiles(
	"model.conf", "policy.csv", extractSubject,
	authz.WithActionResolver(func(procedure string) string {
		if strings.HasPrefix(procedure, "/read.") {
			return "read"
		}
		return "write"
	}),
)
```

## Working with Authentication

This library is designed to work with any authentication system. Common patterns:

**With [connectrpc.com/authn](https://github.com/connectrpc/authn-go):**

```go
import "connectrpc.com/authn"

getIdentity := func(ctx context.Context) any {
	return authn.GetInfo(ctx) // Returns identity set by authn middleware
}

interceptor, err := authz.NewInterceptor(getIdentity, enforcer)
```

**Custom authentication:**

```go
type contextKey struct{}

getIdentity := func(ctx context.Context) any {
	user, _ := ctx.Value(contextKey{}).(*User)
	return user
}

interceptor, err := authz.NewInterceptor(getIdentity, enforcer)
```

## Full Example

See [examples/fullstack](examples/fullstack) for a complete runnable service with:
- JWT token issuance and validation
- `connectrpc.com/authn` middleware
- Casbin RBAC policies
- Decision handler logging
- gRPC reflection
- curl and grpcurl usage examples

## Status

Requires Go 1.26+.

This project follows semantic versioning.
