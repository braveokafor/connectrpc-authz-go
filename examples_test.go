// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

package authz_test

import (
	"context"
	"fmt"
	"log"
	"slices"

	authz "github.com/braveokafor/connectrpc-authz-go"
	"github.com/casbin/casbin/v2/model"
	xormadapter "github.com/casbin/xorm-adapter/v2"
)

// User represents an authenticated user identity.
type User struct {
	Email string
	Roles []string
}

type userContextKey struct{}

// ExampleNewInterceptor demonstrates creating an interceptor with a custom
// authorization function.
func ExampleNewInterceptor() {
	admin := &User{
		Email: "admin@company.com",
		Roles: []string{"admin", "user"},
	}
	regularUser := &User{
		Email: "user@company.com",
		Roles: []string{"user"},
	}

	// Custom authorization logic
	checkAuth := authz.EnforcerFunc(
		func(ctx context.Context, identity any, procedure string) error {
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
		},
	)

	getIdentity := func(ctx context.Context) any {
		user, _ := ctx.Value(userContextKey{}).(*User)
		return user
	}

	interceptor, err := authz.NewInterceptor(getIdentity, checkAuth)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	_ = interceptor // Use with connect.WithInterceptors(interceptor)

	// Demonstrate authorization checks
	err = checkAuth.Enforce(context.Background(), admin, "/admin.v1.AdminService/DeleteUser")
	fmt.Printf("Admin DeleteUser: %v\n", err == nil)

	err = checkAuth.Enforce(context.Background(), regularUser, "/admin.v1.AdminService/DeleteUser")
	fmt.Printf("User DeleteUser: %v\n", err == nil)

	err = checkAuth.Enforce(context.Background(), regularUser, "/user.v1.UserService/GetProfile")
	fmt.Printf("User GetProfile: %v\n", err == nil)

	// Output:
	// Admin DeleteUser: true
	// User DeleteUser: false
	// User GetProfile: true
}

// ExampleWithDecisionHandler demonstrates using the decision handler
// for logging authorization outcomes.
func ExampleWithDecisionHandler() {
	checkAuth := authz.EnforcerFunc(
		func(ctx context.Context, identity any, procedure string) error {
			user := identity.(*User)
			if procedure == "/admin.v1.AdminService/Delete" &&
				!slices.Contains(user.Roles, "admin") {
				return authz.Errorf("requires admin role")
			}
			return nil
		},
	)

	getIdentity := func(ctx context.Context) any {
		user, _ := ctx.Value(userContextKey{}).(*User)
		return user
	}

	onDecision := func(ctx context.Context, d authz.Decision) {
		if d.Allowed {
			log.Printf("ALLOW identity=%v procedure=%s", d.Identity, d.Procedure)
		} else {
			log.Printf("DENY  identity=%v procedure=%s error=%v", d.Identity, d.Procedure, d.Error)
		}
	}

	interceptor, err := authz.NewInterceptor(
		getIdentity,
		checkAuth,
		authz.WithDecisionHandler(onDecision),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	_ = interceptor // Use with connect.WithInterceptors(interceptor)

	fmt.Println("interceptor created with decision handler")

	// Output:
	// interceptor created with decision handler
}

// ExampleNewCasbinEnforcerFromFiles demonstrates creating a Casbin enforcer
// from model and policy files.
func ExampleNewCasbinEnforcerFromFiles() {
	admin := &User{
		Email: "jane@example.com",
		Roles: []string{"admin"},
	}
	regularUser := &User{
		Email: "john@example.com",
		Roles: []string{"user"},
	}

	extractSubject := func(identity any) []string {
		user, ok := identity.(*User)
		if !ok {
			return nil
		}
		return []string{user.Email}
	}

	enforcer, err := authz.NewCasbinEnforcerFromFiles(
		"testdata/casbin/rbac_model.conf",
		"testdata/casbin/rbac_policy.csv",
		extractSubject,
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	ctx := context.Background()

	err = enforcer.Enforce(ctx, admin, "/test.v1.TestService/AdminMethod")
	fmt.Printf("Admin AdminMethod: %v\n", err == nil)

	err = enforcer.Enforce(ctx, regularUser, "/test.v1.TestService/UserMethod")
	fmt.Printf("User UserMethod: %v\n", err == nil)

	err = enforcer.Enforce(ctx, regularUser, "/test.v1.TestService/AdminMethod")
	fmt.Printf("User AdminMethod: %v\n", err == nil)

	// Output:
	// Admin AdminMethod: true
	// User UserMethod: true
	// User AdminMethod: false
}

// ExampleNewCasbinEnforcerFromAdapter demonstrates creating a Casbin enforcer
// with a database adapter and modifying policies at runtime.
func ExampleNewCasbinEnforcerFromAdapter() {
	user := &User{
		Email: "user@company.com",
		Roles: []string{"user"},
	}

	extractSubject := func(identity any) []string {
		u, ok := identity.(*User)
		if !ok {
			return nil
		}
		return []string{u.Email}
	}

	// Load Casbin model from file
	m, err := model.NewModelFromFile("testdata/casbin/model.conf")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Create database adapter (using SQLite in-memory for example)
	adapter, err := xormadapter.NewAdapter("sqlite3", ":memory:")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	enforcer, err := authz.NewCasbinEnforcerFromAdapter(m, adapter, extractSubject)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	ctx := context.Background()

	// Check before adding policy
	err = enforcer.Enforce(ctx, user, "/api.v1.Service/Method")
	fmt.Printf("Before policy: %v\n", err == nil)

	// Add policy to database
	_, _ = enforcer.Enforcer().AddPolicy(user.Email, "/api.v1.Service/Method", "execute")

	// Check after adding policy
	err = enforcer.Enforce(ctx, user, "/api.v1.Service/Method")
	fmt.Printf("After policy: %v\n", err == nil)

	// Remove policy from database
	_, _ = enforcer.Enforcer().RemovePolicy(user.Email, "/api.v1.Service/Method", "execute")

	// Check after removing policy
	err = enforcer.Enforce(ctx, user, "/api.v1.Service/Method")
	fmt.Printf("After removal: %v\n", err == nil)

	// Output:
	// Before policy: false
	// After policy: true
	// After removal: false
}

// ExampleInterceptor demonstrates using the interceptor with Casbin enforcement.
func ExampleInterceptor() {
	admin := &User{
		Email: "jane@example.com",
		Roles: []string{"admin"},
	}
	regularUser := &User{
		Email: "john@example.com",
		Roles: []string{"user"},
	}

	extractSubject := func(identity any) []string {
		user, ok := identity.(*User)
		if !ok {
			return nil
		}
		return []string{user.Email}
	}

	enforcer, err := authz.NewCasbinEnforcerFromFiles(
		"testdata/casbin/rbac_model.conf",
		"testdata/casbin/rbac_policy.csv",
		extractSubject,
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	getIdentity := func(ctx context.Context) any {
		user, _ := ctx.Value(userContextKey{}).(*User)
		return user
	}

	interceptor, err := authz.NewInterceptor(getIdentity, enforcer)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	_ = interceptor // Use with connect.WithInterceptors(interceptor)

	adminCtx := context.WithValue(context.Background(), userContextKey{}, admin)
	userCtx := context.WithValue(context.Background(), userContextKey{}, regularUser)

	err = enforcer.Enforce(adminCtx, admin, "/test.v1.TestService/AdminMethod")
	fmt.Printf("Admin AdminMethod: %v\n", err == nil)

	err = enforcer.Enforce(userCtx, regularUser, "/test.v1.TestService/UserMethod")
	fmt.Printf("User UserMethod: %v\n", err == nil)

	err = enforcer.Enforce(userCtx, regularUser, "/test.v1.TestService/AdminMethod")
	fmt.Printf("User AdminMethod: %v\n", err == nil)

	// Output:
	// Admin AdminMethod: true
	// User UserMethod: true
	// User AdminMethod: false
}
