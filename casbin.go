// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

package authz

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
)

var _ Enforcer = (*CasbinEnforcer)(nil)

// SubjectExtractorFunc extracts Casbin subjects from an identity.
// Return nil or empty to deny with [connect.CodeUnauthenticated].
type SubjectExtractorFunc func(identity any) []string

// CasbinOption configures a [CasbinEnforcer].
type CasbinOption func(*CasbinEnforcer)

// WithActionResolver sets a function that determines the Casbin action
// for a given procedure. The default action is "execute".
func WithActionResolver(fn func(procedure string) string) CasbinOption {
	return func(e *CasbinEnforcer) {
		e.actionResolver = fn
	}
}

// CasbinEnforcer wraps a Casbin enforcer to implement the [Enforcer] interface.
// It performs authorization checks by mapping identity to subjects (via [SubjectExtractorFunc]),
// procedure to object, and resolving the action (default "execute").
// If any subject is authorized, access is granted.
type CasbinEnforcer struct {
	enforcer         *casbin.SyncedCachedEnforcer
	subjectExtractor SubjectExtractorFunc
	actionResolver   func(procedure string) string
}

// NewCasbinEnforcerFromFiles creates a [CasbinEnforcer] from model and policy file paths.
func NewCasbinEnforcerFromFiles(
	modelPath, policyPath string,
	subjectExtractor SubjectExtractorFunc,
	opts ...CasbinOption,
) (*CasbinEnforcer, error) {
	if subjectExtractor == nil {
		return nil, ErrNilSubjectExtractor
	}
	ce, err := casbin.NewSyncedCachedEnforcer(modelPath, policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %w", err)
	}
	e := &CasbinEnforcer{
		enforcer:         ce,
		subjectExtractor: subjectExtractor,
		actionResolver:   func(string) string { return "execute" },
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// NewCasbinEnforcerFromAdapter creates a [CasbinEnforcer] with a casbin model and adapter.
// This allows using database adapters, file system adapters, or any custom storage backend.
func NewCasbinEnforcerFromAdapter(
	m model.Model,
	a persist.Adapter,
	subjectExtractor SubjectExtractorFunc,
	opts ...CasbinOption,
) (*CasbinEnforcer, error) {
	if subjectExtractor == nil {
		return nil, ErrNilSubjectExtractor
	}
	ce, err := casbin.NewSyncedCachedEnforcer(m, a)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %w", err)
	}
	e := &CasbinEnforcer{
		enforcer:         ce,
		subjectExtractor: subjectExtractor,
		actionResolver:   func(string) string { return "execute" },
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// NewCasbinEnforcerFromString creates a [CasbinEnforcer] from model and policy text.
func NewCasbinEnforcerFromString(
	modelText, policyText string,
	subjectExtractor SubjectExtractorFunc,
	opts ...CasbinOption,
) (*CasbinEnforcer, error) {
	if subjectExtractor == nil {
		return nil, ErrNilSubjectExtractor
	}
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("failed to parse model: %w", err)
	}

	a := stringadapter.NewAdapter(policyText)
	ce, err := casbin.NewSyncedCachedEnforcer(m, a)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %w", err)
	}
	e := &CasbinEnforcer{
		enforcer:         ce,
		subjectExtractor: subjectExtractor,
		actionResolver:   func(string) string { return "execute" },
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// Enforce implements the [Enforcer] interface by checking if the identity
// is authorized to access the procedure using Casbin policies.
// Checks all subjects returned by the [SubjectExtractorFunc] - if any subject
// is authorized, access is granted.
func (e *CasbinEnforcer) Enforce(ctx context.Context, identity any, procedure string) error {
	subjects := e.subjectExtractor(identity)

	if len(subjects) == 0 {
		return ErrorUnauthenticated("no subjects found for identity")
	}

	action := e.actionResolver(procedure)

	for _, subject := range subjects {
		allowed, err := e.enforcer.Enforce(subject, procedure, action)
		if err != nil {
			return connect.NewError(
				connect.CodeInternal,
				fmt.Errorf("failed to enforce policy: %w", err),
			)
		}

		if allowed {
			return nil
		}
	}

	return Errorf("permission denied")
}

// Enforcer returns the underlying [casbin.SyncedCachedEnforcer] for advanced operations
// like AddPolicy, RemovePolicy, LoadPolicy, SavePolicy, and GetRolesForUser.
func (e *CasbinEnforcer) Enforcer() *casbin.SyncedCachedEnforcer {
	return e.enforcer
}
