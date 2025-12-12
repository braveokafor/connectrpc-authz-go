// Copyright (c) 2025 Brave Okafor
// SPDX-License-Identifier: MIT

package authz

import (
	"context"
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
)

// CasbinEnforcer wraps a Casbin enforcer to implement the Enforcer interface.
// It performs authorization checks by mapping identity to subject (via user-provided extractor),
// procedure to object, and using "execute" as the action.
type CasbinEnforcer struct {
	enforcer         *casbin.Enforcer
	subjectExtractor func(any) string
}

// NewCasbinEnforcerFromFiles creates a CasbinEnforcer from model and policy file paths.
// The subjectExtractor function converts the identity (from IdentityFunc) to a subject string
// for Casbin enforcement.
func NewCasbinEnforcerFromFiles(
	modelPath, policyPath string,
	subjectExtractor func(any) string,
) (*CasbinEnforcer, error) {
	e, err := casbin.NewEnforcer(modelPath, policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %w", err)
	}
	return &CasbinEnforcer{
		enforcer:         e,
		subjectExtractor: subjectExtractor,
	}, nil
}

// NewCasbinEnforcerFromAdapter creates a CasbinEnforcer with a casbin model and adapter.
// This allows using database adapters, file system adapters, or any custom storage backend.
func NewCasbinEnforcerFromAdapter(
	m model.Model,
	a persist.Adapter,
	subjectExtractor func(any) string,
) (*CasbinEnforcer, error) {
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %w", err)
	}
	return &CasbinEnforcer{
		enforcer:         e,
		subjectExtractor: subjectExtractor,
	}, nil
}

// NewCasbinEnforcerFromString creates a CasbinEnforcer from model and policy text.
// This is useful for testing or when policies are embedded as strings in the application.
func NewCasbinEnforcerFromString(
	modelText, policyText string,
	subjectExtractor func(any) string,
) (*CasbinEnforcer, error) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("failed to parse model: %w", err)
	}

	a := stringadapter.NewAdapter(policyText)
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %w", err)
	}

	return &CasbinEnforcer{
		enforcer:         e,
		subjectExtractor: subjectExtractor,
	}, nil
}

// Enforce implements the Enforcer interface by checking if the identity
// is authorized to access the procedure using Casbin policies.
// The action is always "execute".
func (e *CasbinEnforcer) Enforce(ctx context.Context, identity any, procedure string) error {
	subject := e.subjectExtractor(identity)

	allowed, err := e.enforcer.Enforce(subject, procedure, "execute")
	if err != nil {
		return fmt.Errorf("failed to enforce policy: %w", err)
	}

	if !allowed {
		return Errorf("subject %q denied access to %q", subject, procedure)
	}

	return nil
}

// Enforcer returns the underlying casbin.Enforcer for advanced operations
// like AddPolicy, RemovePolicy, LoadPolicy, SavePolicy, and GetRolesForUser.
func (e *CasbinEnforcer) Enforcer() *casbin.Enforcer {
	return e.enforcer
}
