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
// It performs authorization checks by mapping identity to subjects (via user-provided extractor),
// procedure to object, and using "execute" as the action.
// Supports multi-subject authorization - if any subject is authorized, access is granted.
type CasbinEnforcer struct {
	enforcer         *casbin.Enforcer
	subjectExtractor func(any) []string
}

// NewCasbinEnforcerFromFiles creates a CasbinEnforcer from model and policy file paths.
// The subjectExtractor function converts the identity (from IdentityFunc) to a list of subjects
// for Casbin enforcement. If any subject is authorized, access is granted.
func NewCasbinEnforcerFromFiles(
	modelPath, policyPath string,
	subjectExtractor func(any) []string,
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
// The subjectExtractor function converts the identity to a list of subjects.
// If any subject is authorized, access is granted.
func NewCasbinEnforcerFromAdapter(
	m model.Model,
	a persist.Adapter,
	subjectExtractor func(any) []string,
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
// The subjectExtractor function converts the identity to a list of subjects.
// If any subject is authorized, access is granted.
func NewCasbinEnforcerFromString(
	modelText, policyText string,
	subjectExtractor func(any) []string,
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
// Checks all subjects returned by subjectExtractor - if ANY subject is authorized, access is granted.
func (e *CasbinEnforcer) Enforce(ctx context.Context, identity any, procedure string) error {
	subjects := e.subjectExtractor(identity)

	if len(subjects) == 0 {
		return Errorf("no subjects found for identity")
	}

	for _, subject := range subjects {
		allowed, err := e.enforcer.Enforce(subject, procedure, "execute")
		if err != nil {
			return fmt.Errorf("failed to enforce policy: %w", err)
		}

		if allowed {
			return nil // ANY subject passes
		}
	}

	return Errorf("access denied to procedure %q", procedure)
}

// Enforcer returns the underlying casbin.Enforcer for advanced operations
// like AddPolicy, RemovePolicy, LoadPolicy, SavePolicy, and GetRolesForUser.
func (e *CasbinEnforcer) Enforcer() *casbin.Enforcer {
	return e.enforcer
}
