// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

package authz_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	authz "github.com/braveokafor/connectrpc-authz-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Ensure Interceptor implements connect.Interceptor interface.
var _ connect.Interceptor = &authz.Interceptor{}

const testProcedure = "/test.v1.TestService/TestMethod"

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
			authzError: authz.Errorf("permission denied"),
			wantCode:   connect.CodePermissionDenied,
		},
		{
			name:     "no_identity",
			identity: nil,
			wantCode: connect.CodeUnauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			getIdentity := func(ctx context.Context) any {
				return tt.identity
			}

			enforcer := authz.EnforcerFunc(
				func(ctx context.Context, identity any, procedure string) error {
					assert.Equal(t, testProcedure, procedure)
					return tt.authzError
				},
			)

			interceptor, err := authz.NewInterceptor(getIdentity, enforcer)
			require.NoError(t, err)

			mux := http.NewServeMux()
			mux.Handle(testProcedure, connect.NewUnaryHandler(
				testProcedure,
				func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
					return connect.NewResponse(&emptypb.Empty{}), nil
				},
				connect.WithInterceptors(interceptor),
			))

			srv := startHTTPServer(t, mux)

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
			authzError: authz.Errorf("permission denied"),
			wantCode:   connect.CodePermissionDenied,
		},
		{
			name:     "no_identity",
			identity: nil,
			wantCode: connect.CodeUnauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			getIdentity := func(ctx context.Context) any {
				return tt.identity
			}

			enforcer := authz.EnforcerFunc(
				func(ctx context.Context, identity any, procedure string) error {
					assert.Equal(t, testProcedure, procedure)
					return tt.authzError
				},
			)

			interceptor, err := authz.NewInterceptor(getIdentity, enforcer)
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

func TestInterceptorStreamingClient(t *testing.T) {
	t.Parallel()

	// WrapStreamingClient should be a passthrough for server-side authorization
	getIdentity := func(ctx context.Context) any {
		return "jane@example.com"
	}

	var calledAuthz atomic.Bool
	enforcer := authz.EnforcerFunc(func(ctx context.Context, identity any, procedure string) error {
		calledAuthz.Store(true)
		return nil
	})

	interceptor, err := authz.NewInterceptor(getIdentity, enforcer)
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
	))

	srv := startHTTPServer(t, mux)

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		srv.Client(),
		srv.URL+testProcedure,
		connect.WithInterceptors(interceptor),
	)

	stream := client.CallBidiStream(context.Background())
	t.Cleanup(func() {
		assert.NoError(t, stream.CloseRequest())
	})
	t.Cleanup(func() {
		assert.NoError(t, stream.CloseResponse())
	})

	err = stream.Send(&emptypb.Empty{})
	require.NoError(t, err)

	_, receiveErr := stream.Receive()
	require.NoError(t, receiveErr)

	// WrapStreamingClient is passthrough, so authz should not be called
	assert.False(t, calledAuthz.Load(), "authz should not be called for client-side streaming")
}

func TestNewInterceptorNilArgs(t *testing.T) {
	t.Parallel()

	enforcer := authz.EnforcerFunc(func(ctx context.Context, identity any, procedure string) error {
		return nil
	})
	getIdentity := func(ctx context.Context) any { return "user" }

	_, err := authz.NewInterceptor(nil, enforcer)
	require.ErrorIs(t, err, authz.ErrNilIdentityFunc)

	_, err = authz.NewInterceptor(getIdentity, nil)
	require.ErrorIs(t, err, authz.ErrNilEnforcer)
}

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
			authzError: authz.Errorf("denied"),
		},
		{
			name:      "unauthenticated",
			identity:  nil,
			wantNilID: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got authz.Decision
			handler := func(ctx context.Context, d authz.Decision) {
				got = d
			}

			getIdentity := func(ctx context.Context) any { return tt.identity }
			enforcer := authz.EnforcerFunc(
				func(ctx context.Context, identity any, procedure string) error {
					return tt.authzError
				},
			)

			interceptor, err := authz.NewInterceptor(
				getIdentity,
				enforcer,
				authz.WithDecisionHandler(handler),
			)
			require.NoError(t, err)

			mux := http.NewServeMux()
			mux.Handle(testProcedure, connect.NewUnaryHandler(
				testProcedure,
				func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
					return connect.NewResponse(&emptypb.Empty{}), nil
				},
				connect.WithInterceptors(interceptor),
			))

			srv := startHTTPServer(t, mux)
			client := connect.NewClient[emptypb.Empty, emptypb.Empty](
				srv.Client(),
				srv.URL+testProcedure,
			)
			_, _ = client.CallUnary(context.Background(), connect.NewRequest(&emptypb.Empty{}))

			assert.Equal(t, testProcedure, got.Procedure)
			assert.Equal(t, tt.wantAllowed, got.Allowed)
			if tt.wantNilID {
				assert.Nil(t, got.Identity)
			} else {
				assert.Equal(t, tt.identity, got.Identity)
			}
			if tt.wantAllowed {
				assert.NoError(t, got.Error)
			} else {
				assert.Error(t, got.Error)
			}
		})
	}
}

func TestInferProcedure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		url       string
		wantProc  string
		wantValid bool
	}{
		{
			name:      "valid procedure",
			url:       "https://api.example.com/greet.v1.GreetService/Greet",
			wantProc:  "/greet.v1.GreetService/Greet",
			wantValid: true,
		},
		{
			name:      "valid with query params",
			url:       "https://api.example.com/greet.v1.GreetService/Greet?foo=bar",
			wantProc:  "/greet.v1.GreetService/Greet",
			wantValid: true,
		},
		{
			name:      "invalid - no method",
			url:       "https://api.example.com/greet.v1.GreetService/",
			wantProc:  "/greet.v1.GreetService/",
			wantValid: false,
		},
		{
			name:      "invalid - no service",
			url:       "https://api.example.com/Greet",
			wantProc:  "/Greet",
			wantValid: false,
		},
		{
			name:      "invalid - root path",
			url:       "https://api.example.com/",
			wantProc:  "/",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			u, err := url.Parse(tt.url)
			require.NoError(t, err)

			proc, valid := authz.InferProcedure(u)
			assert.Equal(t, tt.wantProc, proc)
			assert.Equal(t, tt.wantValid, valid)
		})
	}
}

func startHTTPServer(tb testing.TB, h http.Handler) *httptest.Server {
	tb.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	tb.Cleanup(srv.Close)
	return srv
}
