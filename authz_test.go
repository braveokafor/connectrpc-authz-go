// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

package authz_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	authz "github.com/braveokafor/connectrpc-authz-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

const testProcedure = "/test.v1.TestService/TestMethod"

func identityOf(v any) authz.IdentityFunc {
	return func(context.Context) any { return v }
}

func allowAll(ctx context.Context, r *authz.Request) error { return nil }

func TestInterceptorUnary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		identity   any
		authzError error
		wantCode   connect.Code
	}{
		{
			name:     "authorized",
			identity: "jane@example.com",
		},
		{
			name:       "permission_denied",
			identity:   "john@example.com",
			authzError: authz.ErrorPermissionDenied("permission denied"),
			wantCode:   connect.CodePermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			enforcer := authz.EnforcerFunc(
				func(ctx context.Context, r *authz.Request) error {
					assert.Equal(t, testProcedure, r.Spec.Procedure)
					assert.IsType(t, &emptypb.Empty{}, r.Message)
					return tt.authzError
				},
			)

			interceptor, err := authz.NewInterceptor(
				enforcer,
				authz.WithIdentityFunc(identityOf(tt.identity)),
			)
			require.NoError(t, err)

			srv := startUnaryServer(t, interceptor)

			client := connect.NewClient[emptypb.Empty, emptypb.Empty](
				srv.Client(),
				srv.URL+testProcedure,
			)
			_, err = client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))

			if tt.wantCode > 0 {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestInterceptorStreamingHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		identity   any
		authzError error
		wantCode   connect.Code
	}{
		{
			name:     "authorized",
			identity: "jane@example.com",
		},
		{
			name:       "permission_denied",
			identity:   "john@example.com",
			authzError: authz.ErrorPermissionDenied("permission denied"),
			wantCode:   connect.CodePermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			enforcer := authz.EnforcerFunc(
				func(ctx context.Context, r *authz.Request) error {
					assert.Equal(t, testProcedure, r.Spec.Procedure)
					assert.Nil(t, r.Message, "streams authorise before any message")
					assert.NotEmpty(t, r.Peer.Addr, "stream requests carry the peer")
					assert.NotEmpty(
						t,
						r.Header.Get("Content-Type"),
						"stream requests carry headers",
					)
					return tt.authzError
				},
			)

			interceptor, err := authz.NewInterceptor(
				enforcer,
				authz.WithIdentityFunc(identityOf(tt.identity)),
			)
			require.NoError(t, err)

			mux := http.NewServeMux()
			mux.Handle(testProcedure, connect.NewBidiStreamHandler(
				testProcedure,
				func(ctx context.Context, stream *connect.BidiStream[emptypb.Empty, emptypb.Empty]) error {
					_, err := stream.Receive()
					if err != nil {
						return err
					}
					return stream.Send(&emptypb.Empty{})
				},
				connect.WithInterceptors(interceptor),
			))

			srv := startHTTPServer(t, mux)

			client := connect.NewClient[emptypb.Empty, emptypb.Empty](
				srv.Client(),
				srv.URL+testProcedure,
			)

			stream := client.CallBidiStream(context.Background())
			t.Cleanup(func() {
				assert.NoError(t, stream.CloseRequest())
			})
			t.Cleanup(func() {
				assert.NoError(t, stream.CloseResponse())
			})

			err = stream.Send(&emptypb.Empty{})
			require.NoError(t, err) // Send might succeed even if authz fails

			_, receiveErr := stream.Receive()

			if tt.wantCode > 0 {
				require.Error(t, receiveErr)
				assert.Equal(t, tt.wantCode, connect.CodeOf(receiveErr))
			} else {
				require.NoError(t, receiveErr)
			}
		})
	}
}

// Guards the v0.4.0 bug: the interceptor attached to a connect CLIENT denied
// the client's own outbound calls.
func TestInterceptorClientSidePassthrough(t *testing.T) {
	t.Parallel()

	var calledAuthz atomic.Bool
	enforcer := authz.EnforcerFunc(func(ctx context.Context, r *authz.Request) error {
		calledAuthz.Store(true)
		return authz.ErrorPermissionDenied("must never run on clients")
	})

	interceptor, err := authz.NewInterceptor(enforcer, authz.WithIdentityFunc(identityOf(nil)))
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.Handle(testProcedure, connect.NewUnaryHandler(
		testProcedure,
		func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
	))
	srv := startHTTPServer(t, mux)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		srv.Client(),
		srv.URL+testProcedure,
		connect.WithInterceptors(interceptor),
	)
	_, err = client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	require.NoError(t, err)
	assert.False(t, calledAuthz.Load(), "authz must not run on client interceptor chains")
}

func TestNewInterceptorValidation(t *testing.T) {
	t.Parallel()

	_, err := authz.NewInterceptor(nil, authz.WithIdentityFunc(identityOf("user")))
	require.ErrorIs(t, err, authz.ErrNilEnforcer)

	_, err = authz.NewInterceptor(authz.EnforcerFunc(allowAll))
	require.NoError(t, err) // an identity source is optional
}

func TestAnonymousReachesEnforcer(t *testing.T) {
	t.Parallel()

	var sawNilIdentity atomic.Bool
	enforcer := authz.EnforcerFunc(func(ctx context.Context, r *authz.Request) error {
		if r.Identity == nil {
			sawNilIdentity.Store(true)
		}
		return nil
	})

	interceptor, err := authz.NewInterceptor(enforcer, authz.WithIdentityFunc(identityOf(nil)))
	require.NoError(t, err)
	srv := startUnaryServer(t, interceptor)
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](srv.Client(), srv.URL+testProcedure)
	_, err = client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	require.NoError(t, err)
	assert.True(t, sawNilIdentity.Load(), "the enforcer decides anonymous requests")
}

func TestPanicRecovery(t *testing.T) {
	t.Parallel()

	var got authz.Decision
	enforcer := authz.EnforcerFunc(func(ctx context.Context, r *authz.Request) error {
		panic("boom")
	})
	interceptor, err := authz.NewInterceptor(enforcer,
		authz.WithIdentityFunc(identityOf("user")),
		authz.WithDecisionHandler(func(ctx context.Context, d authz.Decision) { got = d }),
	)
	require.NoError(t, err)

	srv := startUnaryServer(t, interceptor)
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](srv.Client(), srv.URL+testProcedure)

	_, err = client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	assert.NotContains(t, err.Error(), "boom", "panic detail must not reach the wire")
	require.Error(t, got.Error)
	assert.Contains(t, got.Error.Error(), "boom")
	assert.False(t, got.Allowed)
}

func TestErrorSanitization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		enforceErr  error
		wantCode    connect.Code
		wantMessage string // checked as a substring of the wire error
		leakedText  string // checked to be absent from the wire error
	}{
		{
			name:        "uncoded_error_sanitized",
			enforceErr:  errors.New("secret-internal-detail"),
			wantCode:    connect.CodePermissionDenied,
			wantMessage: "permission denied",
			leakedText:  "secret-internal-detail",
		},
		{
			name: "coded_error_passes_through",
			enforceErr: connect.NewError(
				connect.CodeUnavailable,
				errors.New("policy backend down"),
			),
			wantCode:    connect.CodeUnavailable,
			wantMessage: "policy backend down",
		},
		{
			name: "wrapped_coded_error_passes_through",
			enforceErr: &wrapError{
				msg:   "outer",
				inner: authz.ErrorUnauthenticated("token expired"),
			},
			wantCode:    connect.CodeUnauthenticated,
			wantMessage: "token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got authz.Decision
			enforcer := authz.EnforcerFunc(func(ctx context.Context, r *authz.Request) error {
				return tt.enforceErr
			})
			interceptor, err := authz.NewInterceptor(enforcer,
				authz.WithIdentityFunc(identityOf("user")),
				authz.WithDecisionHandler(func(ctx context.Context, d authz.Decision) { got = d }),
			)
			require.NoError(t, err)

			srv := startUnaryServer(t, interceptor)
			client := connect.NewClient[emptypb.Empty, emptypb.Empty](
				srv.Client(),
				srv.URL+testProcedure,
			)

			_, err = client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))
			require.Error(t, err)
			assert.Equal(t, tt.wantCode, connect.CodeOf(err))
			assert.Contains(t, err.Error(), tt.wantMessage)
			if tt.leakedText != "" {
				assert.NotContains(t, err.Error(), tt.leakedText)
			}
			assert.Equal(t, tt.enforceErr, got.Error, "Decision carries the original error")
		})
	}
}

type wrapError struct {
	msg   string
	inner error
}

func (e *wrapError) Error() string { return e.msg + ": " + e.inner.Error() }
func (e *wrapError) Unwrap() error { return e.inner }

func TestDecisionHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		identity    any
		authzError  error
		wantAllowed bool
		wantNilID   bool
	}{
		{
			name:        "allowed",
			identity:    "jane@example.com",
			wantAllowed: true,
		},
		{
			name:       "denied",
			identity:   "john@example.com",
			authzError: authz.ErrorPermissionDenied("denied"),
		},
		{
			name:        "anonymous",
			identity:    nil,
			wantAllowed: true,
			wantNilID:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got authz.Decision
			enforcer := authz.EnforcerFunc(func(ctx context.Context, r *authz.Request) error {
				return tt.authzError
			})

			interceptor, err := authz.NewInterceptor(enforcer,
				authz.WithIdentityFunc(identityOf(tt.identity)),
				authz.WithDecisionHandler(func(ctx context.Context, d authz.Decision) { got = d }),
			)
			require.NoError(t, err)

			srv := startUnaryServer(t, interceptor)
			client := connect.NewClient[emptypb.Empty, emptypb.Empty](
				srv.Client(),
				srv.URL+testProcedure,
			)
			_, _ = client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))

			require.NotNil(t, got.Request, "decision carries the request it was made on")
			assert.Equal(t, testProcedure, got.Request.Spec.Procedure)
			assert.IsType(t, &emptypb.Empty{}, got.Request.Message)
			assert.Equal(t, tt.wantAllowed, got.Allowed)
			assert.Equal(t, tt.wantAllowed, got.Error == nil, "Allowed mirrors Error")
			assert.Positive(t, got.Duration)
			if tt.wantNilID {
				assert.Nil(t, got.Request.Identity)
			} else {
				assert.Equal(t, tt.identity, got.Request.Identity)
			}
		})
	}
}

func startUnaryServer(tb testing.TB, interceptor *authz.Interceptor) *httptest.Server {
	tb.Helper()
	mux := http.NewServeMux()
	mux.Handle(testProcedure, connect.NewUnaryHandler(
		testProcedure,
		func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(interceptor),
	))
	return startHTTPServer(tb, mux)
}

func startHTTPServer(tb testing.TB, h http.Handler) *httptest.Server {
	tb.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	tb.Cleanup(srv.Close)
	return srv
}
