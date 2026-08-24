// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

package casbin_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	authz "github.com/braveokafor/connectrpc-authz-go"
	casbin "github.com/braveokafor/connectrpc-authz-go/casbin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const modelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

const policyText = `
p, roleA, obj1, execute
p, roleB, obj2, execute
`

// rolesOf treats the identity as its role list.
func rolesOf(r *authz.Request) []string {
	roles, _ := r.Identity.([]string)
	return roles
}

func TestConstructorValidation(t *testing.T) {
	t.Parallel()

	_, err := casbin.New(nil, rolesOf)
	require.ErrorIs(t, err, casbin.ErrNilEngine)

	_, err = casbin.NewFromString(modelText, policyText, nil)
	require.ErrorIs(t, err, casbin.ErrNilSubjectsFunc)

	_, err = casbin.NewFromString("invalid model", policyText, rolesOf)
	require.Error(t, err)
}

// TestEnforceSemantics pins the binding's contracts.
func TestEnforceSemantics(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	e, err := casbin.NewFromString(modelText, policyText, rolesOf)
	require.NoError(t, err)

	isConnectErr := func(err error) bool {
		var cerr *connect.Error
		return errors.As(err, &cerr)
	}

	t.Run("exists_subject_allowing_procedure", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, e.Enforce(ctx, &authz.Request{
			Identity: []string{"roleB", "roleA"},
			Spec:     connect.Spec{Procedure: "obj1"},
		}))
	})

	t.Run("no_subject_allows_procedure", func(t *testing.T) {
		t.Parallel()
		err := e.Enforce(ctx, &authz.Request{
			Identity: []string{"roleA"},
			Spec:     connect.Spec{Procedure: "obj2"},
		})
		require.Error(t, err)
		assert.False(
			t,
			isConnectErr(err),
			"deny detail stays uncoded for the interceptor to sanitize",
		)
		assert.Contains(t, err.Error(), "obj2")
	})

	t.Run("anonymous_without_subjects", func(t *testing.T) {
		t.Parallel()
		err := e.Enforce(ctx, &authz.Request{Identity: nil})
		require.Error(t, err)
		assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	})

	t.Run("identified_without_subjects", func(t *testing.T) {
		t.Parallel()
		err := e.Enforce(ctx, &authz.Request{Identity: []string{}})
		require.Error(t, err)
		assert.False(t, isConnectErr(err), "an identified caller must not get Unauthenticated")
	})
}
