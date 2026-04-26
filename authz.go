// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

// Package authz provides authorization interceptors for ConnectRPC.
package authz

import (
	"context"
	"net/url"
	"strings"

	"connectrpc.com/connect"
)

// IdentityFunc extracts the authenticated identity from the request context.
// It should return the identity information (e.g., user, roles, claims) or nil
// if no identity is present. The returned value is passed to [Enforcer.Enforce].
//
// Implementations must be safe to call concurrently.
type IdentityFunc func(context.Context) any

// Enforcer checks whether the given identity is authorized to access the
// specified procedure. Return nil if authorized, or an error (typically
// produced with [Errorf]) if not.
//
// Implementations must be safe to call concurrently.
type Enforcer interface {
	Enforce(ctx context.Context, identity any, procedure string) error
}

// EnforcerFunc is an adapter to use ordinary functions as [Enforcer]s.
type EnforcerFunc func(ctx context.Context, identity any, procedure string) error

func (f EnforcerFunc) Enforce(ctx context.Context, identity any, procedure string) error {
	return f(ctx, identity, procedure)
}

// Decision represents the outcome of an authorization check.
type Decision struct {
	Identity  any // nil if unauthenticated
	Procedure string
	Allowed   bool
	Error     error // nil if allowed
}

// DecisionFunc is called after every authorization decision.
// Called synchronously - launch a goroutine inside if you need async.
type DecisionFunc func(ctx context.Context, decision Decision)

// InterceptorOption configures an [Interceptor].
type InterceptorOption func(*Interceptor)

// WithDecisionHandler registers a callback invoked after every authorization
// decision (both allow and deny).
func WithDecisionHandler(fn DecisionFunc) InterceptorOption {
	return func(i *Interceptor) {
		i.onDecision = fn
	}
}

// Interceptor is a [connect.Interceptor] that enforces authorization
// for RPC requests. It extracts the identity using the provided [IdentityFunc],
// then checks authorization using the provided [Enforcer].
//
// Authorization is checked once at the start of each RPC or stream.
// If the identity is nil, the interceptor returns [connect.CodeUnauthenticated].
// If authorization fails, the interceptor returns [connect.CodePermissionDenied].
//
// This interceptor is intended for use on server handlers.
type Interceptor struct {
	getIdentity IdentityFunc
	enforcer    Enforcer
	onDecision  DecisionFunc
}

var _ connect.Interceptor = (*Interceptor)(nil)

// NewInterceptor creates an [Interceptor] that enforces authorization
// using the provided identity extraction function and enforcer.
func NewInterceptor(
	getIdentity IdentityFunc,
	enforcer Enforcer,
	opts ...InterceptorOption,
) (*Interceptor, error) {
	if getIdentity == nil {
		return nil, ErrNilIdentityFunc
	}
	if enforcer == nil {
		return nil, ErrNilEnforcer
	}
	i := &Interceptor{
		getIdentity: getIdentity,
		enforcer:    enforcer,
	}
	for _, opt := range opts {
		opt(i)
	}
	return i, nil
}

// WrapUnary implements [connect.Interceptor].
func (i *Interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := i.authorize(ctx, req.Spec().Procedure); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient implements [connect.Interceptor].
// For server-side authorization, this is a passthrough.
func (i *Interceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements [connect.Interceptor].
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
		err := ErrorUnauthenticated("no identity found in context")
		i.notify(ctx, Decision{Procedure: procedure, Error: err})
		return err
	}
	err := i.enforcer.Enforce(ctx, identity, procedure)
	i.notify(ctx, Decision{
		Identity:  identity,
		Procedure: procedure,
		Allowed:   err == nil,
		Error:     err,
	})
	return err
}

func (i *Interceptor) notify(ctx context.Context, d Decision) {
	if i.onDecision != nil {
		i.onDecision(ctx, d)
	}
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
