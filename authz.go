// Copyright (c) 2025 Brave Okafor
// SPDX-License-Identifier: MIT

// Package authz provides authorization interceptors for ConnectRPC.
package authz

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"connectrpc.com/connect"
)

// IdentityFunc extracts the authenticated identity from the request context.
// It should return the identity information (e.g., user, roles, claims) or nil
// if no identity is present. The returned value is passed to AuthzFunc.
//
// Implementations must be safe to call concurrently.
type IdentityFunc func(context.Context) any

// AuthzFunc checks whether the given identity is authorized to access the
// specified procedure. It should return nil if authorized, or an error if not.
// The error is typically produced with Errorf, but any error will do.
//
// Implementations must be safe to call concurrently.
type AuthzFunc func(ctx context.Context, identity any, procedure string) error

// Enforcer is an interface for authorization enforcers.
// Implementations check if an identity is authorized to access a procedure.
type Enforcer interface {
	Enforce(ctx context.Context, identity any, procedure string) error
}

// EnforcerFunc converts an Enforcer to an AuthzFunc.
// This allows using enforcer implementations with NewInterceptor.
func EnforcerFunc(e Enforcer) AuthzFunc {
	return func(ctx context.Context, identity any, procedure string) error {
		return e.Enforce(ctx, identity, procedure)
	}
}

// Interceptor is a [connect.Interceptor] that enforces authorization
// for RPC requests. It extracts the identity using the provided IdentityFunc,
// then checks authorization using the provided AuthzFunc.
//
// Authorization is checked once at the start of each RPC or stream.
// If the identity is nil, the interceptor returns CodeUnauthenticated.
// If authorization fails, the interceptor returns CodePermissionDenied.
//
// This interceptor is intended for use on server handlers.
type Interceptor struct {
	getIdentity IdentityFunc
	authz       AuthzFunc
}

var _ connect.Interceptor = &Interceptor{}

// NewInterceptor creates an Interceptor that enforces authorization
// using the provided identity extraction and authorization functions.
//
// The interceptor extracts the identity using getIdentity, then calls authz
// to check authorization. If identity is nil, returns CodeUnauthenticated.
// If authorization fails, returns CodePermissionDenied.
func NewInterceptor(getIdentity IdentityFunc, authz AuthzFunc) *Interceptor {
	return &Interceptor{
		getIdentity: getIdentity,
		authz:       authz,
	}
}

// WrapUnary implements connect.Interceptor.
func (i *Interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := i.authorize(ctx, req.Spec().Procedure); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor.
// For server-side authorization, this is a passthrough.
func (i *Interceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
func (i *Interceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if err := i.authorize(ctx, conn.Spec().Procedure); err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

func (i *Interceptor) authorize(ctx context.Context, procedure string) error {
	identity := i.getIdentity(ctx)
	if identity == nil {
		return ErrorUnauthenticated("no identity found in context")
	}
	return i.authz(ctx, identity, procedure)
}

// Errorf is a convenience function that returns an error coded with
// connect.CodePermissionDenied. Use this when authorization fails.
func Errorf(template string, args ...any) *connect.Error {
	return connect.NewError(connect.CodePermissionDenied, fmt.Errorf(template, args...))
}

// ErrorUnauthenticated is a convenience function that returns an error coded
// with connect.CodeUnauthenticated. Use this when no identity is found.
func ErrorUnauthenticated(template string, args ...any) *connect.Error {
	return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf(template, args...))
}

// InferProcedure returns the inferred RPC procedure from a URL. It's returned
// in the form "/service/method" if a valid suffix is found. If the URL doesn't
// contain a service and method, the entire path and false is returned.
func InferProcedure(u *url.URL) (string, bool) {
	path := u.Path
	ultimate := strings.LastIndex(path, "/")
	if ultimate < 0 {
		return u.Path, false
	}
	penultimate := strings.LastIndex(path[:ultimate], "/")
	if penultimate < 0 {
		return u.Path, false
	}
	procedure := path[penultimate:]
	// Ensure that the service and method are non-empty.
	if ultimate == len(path)-1 || penultimate == ultimate-1 {
		return u.Path, false
	}
	return procedure, true
}
