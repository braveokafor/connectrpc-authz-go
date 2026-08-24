// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

// Package casbin provides a Casbin-backed [authz.Enforcer].
package casbin

import (
	"context"
	"errors"
	"fmt"

	authz "github.com/braveokafor/connectrpc-authz-go"
	casbinv2 "github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
)

var (
	// ErrNilEngine means [New] received a nil engine.
	ErrNilEngine = errors.New("casbin: engine must not be nil")

	// ErrNilSubjectsFunc means a constructor received a nil [SubjectsFunc].
	ErrNilSubjectsFunc = errors.New("casbin: subjects func must not be nil")
)

// SubjectsFunc derives the Casbin subjects from the request identity.
type SubjectsFunc func(r *authz.Request) []string

// Enforcer is a Casbin [authz.Enforcer].
type Enforcer struct {
	engine   casbinv2.IEnforcer
	subjects SubjectsFunc
}

var _ authz.Enforcer = (*Enforcer)(nil)

// New wraps an existing Casbin engine.
func New(engine casbinv2.IEnforcer, subjects SubjectsFunc) (*Enforcer, error) {
	if engine == nil {
		return nil, ErrNilEngine
	}
	if subjects == nil {
		return nil, ErrNilSubjectsFunc
	}
	return &Enforcer{engine: engine, subjects: subjects}, nil
}

// NewFromString builds a SyncedEnforcer from model and policy text.
func NewFromString(modelText, policyText string, subjects SubjectsFunc) (*Enforcer, error) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("casbin: parse model: %w", err)
	}
	engine, err := casbinv2.NewSyncedEnforcer(m, stringadapter.NewAdapter(policyText))
	if err != nil {
		return nil, fmt.Errorf("casbin: create enforcer: %w", err)
	}
	return New(engine, subjects)
}

// Engine returns the underlying Casbin engine. Runtime mutation needs a concurrency-safe engine.
func (e *Enforcer) Engine() casbinv2.IEnforcer {
	return e.engine
}

// Enforce implements [authz.Enforcer]. Missing identity is Unauthenticated, else uncoded.
func (e *Enforcer) Enforce(_ context.Context, r *authz.Request) error {
	subjects := e.subjects(r)
	if len(subjects) == 0 {
		if r.Identity == nil {
			return authz.ErrorUnauthenticated("authentication required")
		}
		return errors.New("casbin: no subjects derived for identity")
	}
	for _, subject := range subjects {
		ok, err := e.engine.Enforce(subject, r.Spec.Procedure, "execute")
		if err != nil {
			return fmt.Errorf("casbin: enforce %q: %w", r.Spec.Procedure, err)
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("casbin: no policy allows %s", r.Spec.Procedure)
}
