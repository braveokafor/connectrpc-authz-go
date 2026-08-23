// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

package authz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
)

// Request is the read-only input an [Enforcer] sees for one RPC.
type Request struct {
	// Identity is nil for an unauthenticated caller.
	Identity any
	Spec     connect.Spec
	Peer     connect.Peer
	Header   http.Header
	// Message is nil on streaming RPCs.
	Message any
}

// Enforcer authorises an RPC. Return nil to allow, or a *connect.Error to deny with a code.
type Enforcer interface {
	Enforce(ctx context.Context, r *Request) error
}

// EnforcerFunc adapts a function to [Enforcer].
type EnforcerFunc func(ctx context.Context, r *Request) error

func (f EnforcerFunc) Enforce(ctx context.Context, r *Request) error {
	return f(ctx, r)
}

// ErrorPermissionDenied returns a [connect.CodePermissionDenied] error.
func ErrorPermissionDenied(template string, args ...any) *connect.Error {
	return connect.NewError(connect.CodePermissionDenied, fmt.Errorf(template, args...))
}

// ErrorUnauthenticated returns a [connect.CodeUnauthenticated] error.
func ErrorUnauthenticated(template string, args ...any) *connect.Error {
	return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf(template, args...))
}

// IdentityFunc returns the authenticated identity in ctx, or nil.
type IdentityFunc func(ctx context.Context) any

// Decision records one authorisation outcome.
type Decision struct {
	Request  *Request
	Duration time.Duration
	Allowed  bool
	// Error is the Enforcer's raw error, before wire sanitisation.
	Error error
}

// DecisionFunc runs after every decision, synchronously.
type DecisionFunc func(ctx context.Context, decision Decision)

// Option configures an [Interceptor].
type Option func(*Interceptor)

// WithIdentityFunc sets the identity source.
func WithIdentityFunc(fn IdentityFunc) Option {
	return func(i *Interceptor) {
		i.getIdentity = fn
	}
}

// WithDecisionHandler registers a callback run after every decision.
func WithDecisionHandler(fn DecisionFunc) Option {
	return func(i *Interceptor) {
		i.onDecision = fn
	}
}

// Interceptor authorises server RPCs with an [Enforcer], and is a no-op on clients.
type Interceptor struct {
	enforcer    Enforcer
	getIdentity IdentityFunc
	onDecision  DecisionFunc
}

var _ connect.Interceptor = (*Interceptor)(nil)

// ErrNilEnforcer means the [Enforcer] given to [NewInterceptor] was nil.
var ErrNilEnforcer = errors.New("authz: enforcer must not be nil")

func NewInterceptor(enforcer Enforcer, opts ...Option) (*Interceptor, error) {
	if enforcer == nil {
		return nil, ErrNilEnforcer
	}
	i := &Interceptor{enforcer: enforcer}
	for _, opt := range opts {
		opt(i)
	}
	return i, nil
}

// WrapUnary implements [connect.Interceptor].
func (i *Interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Spec().IsClient {
			return next(ctx, req)
		}
		if err := i.authorize(ctx, &Request{
			Spec:    req.Spec(),
			Peer:    req.Peer(),
			Header:  req.Header(),
			Message: req.Any(),
		}); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient implements [connect.Interceptor] as a passthrough.
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
		if err := i.authorize(ctx, &Request{
			Spec:   conn.Spec(),
			Peer:   conn.Peer(),
			Header: conn.RequestHeader(),
		}); err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

func (i *Interceptor) authorize(ctx context.Context, r *Request) error {
	if i.getIdentity != nil {
		r.Identity = i.getIdentity(ctx)
	}
	start := time.Now()
	err := i.enforce(ctx, r)
	if i.onDecision != nil {
		i.onDecision(
			ctx,
			Decision{Request: r, Duration: time.Since(start), Allowed: err == nil, Error: err},
		)
	}
	if err == nil {
		return nil
	}
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return cerr
	}
	return ErrorPermissionDenied("permission denied")
}

// enforce runs the Enforcer with panic containment.
func (i *Interceptor) enforce(ctx context.Context, r *Request) (err error) {
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				panic(p)
			}
			err = fmt.Errorf("authz: enforcer panic: %v", p)
		}
	}()
	return i.enforcer.Enforce(ctx, r)
}
