// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

package authz_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	authz "github.com/braveokafor/connectrpc-authz-go"
	"github.com/casbin/casbin/v2/model"
	xormadapter "github.com/casbin/xorm-adapter/v2"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestNewCasbinEnforcerFromFiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		modelPath   string
		policyPath  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid files",
			modelPath:  "testdata/casbin/model.conf",
			policyPath: "testdata/casbin/policy.csv",
			wantErr:    false,
		},
		{
			name:        "invalid path",
			modelPath:   "/nonexistent/model.conf",
			policyPath:  "/nonexistent/policy.csv",
			wantErr:     true,
			errContains: "failed to create enforcer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			enforcer, err := authz.NewCasbinEnforcerFromFiles(
				tt.modelPath,
				tt.policyPath,
				func(identity any) []string {
					return []string{identity.(string)}
				},
			)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, enforcer)
			}
		})
	}
}

func TestNewCasbinEnforcerFromString(t *testing.T) {
	t.Parallel()

	const (
		policyText = `p, jane@example.com, /test.v1.TestService/TestMethod, execute`
		modelText  = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	)

	tests := []struct {
		name        string
		modelText   string
		policyText  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid model and policy",
			modelText:  modelText,
			policyText: policyText,
			wantErr:    false,
		},
		{
			name:        "invalid model syntax",
			modelText:   "invalid model",
			policyText:  policyText,
			wantErr:     true,
			errContains: "failed to parse model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			enforcer, err := authz.NewCasbinEnforcerFromString(
				tt.modelText,
				tt.policyText,
				func(identity any) []string {
					return []string{identity.(string)}
				},
			)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, enforcer)
			}
		})
	}
}

func TestNewCasbinEnforcerFromAdapter(t *testing.T) {
	t.Parallel()

	t.Run("xorm adapter with sqlite", func(t *testing.T) {
		t.Parallel()
		m, err := model.NewModelFromFile("testdata/casbin/model.conf")
		require.NoError(t, err)

		// In-memory SQLite adapter
		a, err := xormadapter.NewAdapter("sqlite3", ":memory:")
		require.NoError(t, err)

		enforcer, err := authz.NewCasbinEnforcerFromAdapter(
			m,
			a,
			func(identity any) []string {
				return []string{identity.(string)}
			},
		)
		require.NoError(t, err)
		require.NotNil(t, enforcer)

		_, err = enforcer.Enforcer().
			AddPolicy("jane@example.com", "/test.v1.TestService/TestMethod", "execute")
		require.NoError(t, err)

		err = enforcer.Enforce(
			context.Background(),
			"jane@example.com",
			"/test.v1.TestService/TestMethod",
		)
		require.NoError(t, err)
	})
}

func TestCasbinEnforcer_Enforce(t *testing.T) {
	t.Parallel()

	enforcer, err := authz.NewCasbinEnforcerFromFiles(
		"testdata/casbin/model.conf",
		"testdata/casbin/policy.csv",
		func(identity any) []string {
			return []string{identity.(string)}
		},
	)
	require.NoError(t, err)

	tests := []struct {
		name      string
		identity  any
		procedure string
		wantErr   bool
	}{
		{
			name:      "authorized",
			identity:  "jane@example.com",
			procedure: "/test.v1.TestService/GetData",
			wantErr:   false,
		},
		{
			name:      "permission denied",
			identity:  "jane@example.com",
			procedure: "/test.v1.TestService/UpdateData",
			wantErr:   true,
		},
		{
			name:      "different user authorized",
			identity:  "john@example.com",
			procedure: "/test.v1.TestService/UpdateData",
			wantErr:   false,
		},
		{
			name:      "empty identity",
			identity:  "",
			procedure: "/test.v1.TestService/GetData",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := enforcer.Enforce(context.Background(), tt.identity, tt.procedure)
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCasbinEnforcer_RBAC(t *testing.T) {
	t.Parallel()

	enforcer, err := authz.NewCasbinEnforcerFromFiles(
		"testdata/casbin/rbac_model.conf",
		"testdata/casbin/rbac_policy.csv",
		func(identity any) []string {
			return []string{identity.(string)}
		},
	)
	require.NoError(t, err)

	tests := []struct {
		name      string
		identity  string
		procedure string
		wantErr   bool
	}{
		{
			name:      "admin role has admin access",
			identity:  "jane@example.com",
			procedure: "/test.v1.TestService/AdminMethod",
			wantErr:   false,
		},
		{
			name:      "user role denied admin access",
			identity:  "john@example.com",
			procedure: "/test.v1.TestService/AdminMethod",
			wantErr:   true,
		},
		{
			name:      "user role has user access",
			identity:  "john@example.com",
			procedure: "/test.v1.TestService/UserMethod",
			wantErr:   false,
		},
		{
			name:      "admin role denied user access",
			identity:  "jane@example.com",
			procedure: "/test.v1.TestService/UserMethod",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := enforcer.Enforce(context.Background(), tt.identity, tt.procedure)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCasbinEnforcer_UnderlyingEnforcer(t *testing.T) {
	t.Parallel()

	enforcer, err := authz.NewCasbinEnforcerFromFiles(
		"testdata/casbin/model.conf",
		"testdata/casbin/policy.csv",
		func(identity any) []string {
			return []string{identity.(string)}
		},
	)
	require.NoError(t, err)

	underlying := enforcer.Enforcer()
	require.NotNil(t, underlying)

	_, err = underlying.AddPolicy(
		"chris@example.com",
		"/test.v1.TestService/DeleteData",
		"execute",
	)
	require.NoError(t, err)

	err = enforcer.Enforce(
		context.Background(),
		"chris@example.com",
		"/test.v1.TestService/DeleteData",
	)
	require.NoError(t, err)
}

func TestCasbinEnforcer_Integration(t *testing.T) {
	t.Parallel()

	const testProcedure = "/test.v1.TestService/GetData"

	enforcer, err := authz.NewCasbinEnforcerFromFiles(
		"testdata/casbin/model.conf",
		"testdata/casbin/policy.csv",
		func(identity any) []string {
			if identity == nil {
				return nil
			}
			return []string{identity.(string)}
		},
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		identity any
		wantCode connect.Code
	}{
		{
			name:     "authorized",
			identity: "jane@example.com",
		},
		{
			name:     "permission denied",
			identity: "john@example.com",
			wantCode: connect.CodePermissionDenied,
		},
		{
			name:     "no identity",
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

func TestCasbinEnforcer_MultiRole(t *testing.T) {
	t.Parallel()

	type userWithRoles struct {
		Email string
		Roles []string
	}

	extractSubjects := func(identity any) []string {
		user, ok := identity.(*userWithRoles)
		if !ok || len(user.Roles) == 0 {
			return nil
		}
		return user.Roles
	}

	enforcer, err := authz.NewCasbinEnforcerFromFiles(
		"testdata/casbin/multirole_model.conf",
		"testdata/casbin/multirole_policy.csv",
		extractSubjects,
	)
	require.NoError(t, err)

	tests := []struct {
		name      string
		user      *userWithRoles
		procedure string
		wantCode  connect.Code
	}{
		{
			name: "one role matches - admin",
			user: &userWithRoles{
				Email: "jane@example.com",
				Roles: []string{"user", "admin"},
			},
			procedure: "/test.v1.TestService/AdminMethod",
		},
		{
			name: "one role matches - user",
			user: &userWithRoles{
				Email: "john@example.com",
				Roles: []string{"guest", "user"},
			},
			procedure: "/test.v1.TestService/UserMethod",
		},
		{
			name: "no roles match",
			user: &userWithRoles{
				Email: "guest@example.com",
				Roles: []string{"guest", "visitor"},
			},
			procedure: "/test.v1.TestService/AdminMethod",
			wantCode:  connect.CodePermissionDenied,
		},
		{
			name: "empty roles array",
			user: &userWithRoles{
				Email: "empty@example.com",
				Roles: []string{},
			},
			procedure: "/test.v1.TestService/AdminMethod",
			wantCode:  connect.CodeUnauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := enforcer.Enforce(context.Background(), tt.user, tt.procedure)
			if tt.wantCode > 0 {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCasbinEnforcer_NilSubjectExtractor(t *testing.T) {
	t.Parallel()

	_, err := authz.NewCasbinEnforcerFromFiles(
		"testdata/casbin/model.conf",
		"testdata/casbin/policy.csv",
		nil,
	)
	require.ErrorIs(t, err, authz.ErrNilSubjectExtractor)
}

func TestCasbinEnforcer_WithActionResolver(t *testing.T) {
	t.Parallel()

	const (
		modelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
		policyText = `
p, jane@example.com, /test.v1.TestService/GetData, read
p, jane@example.com, /test.v1.TestService/UpdateData, write
`
	)

	actionResolver := func(procedure string) string {
		switch {
		case len(procedure) > 4 && procedure[len(procedure)-7:] == "GetData":
			return "read"
		default:
			return "write"
		}
	}

	enforcer, err := authz.NewCasbinEnforcerFromString(
		modelText,
		policyText,
		func(identity any) []string {
			return []string{identity.(string)}
		},
		authz.WithActionResolver(actionResolver),
	)
	require.NoError(t, err)

	// read action matches
	err = enforcer.Enforce(context.Background(), "jane@example.com", "/test.v1.TestService/GetData")
	require.NoError(t, err)

	// write action matches
	err = enforcer.Enforce(
		context.Background(),
		"jane@example.com",
		"/test.v1.TestService/UpdateData",
	)
	require.NoError(t, err)

	// read action on write-only procedure - denied
	err = enforcer.Enforce(
		context.Background(),
		"jane@example.com",
		"/test.v1.TestService/DeleteData",
	)
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}
