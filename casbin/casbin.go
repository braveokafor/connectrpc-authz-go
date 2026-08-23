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

	// ErrNilObjectsFunc means [WithObjects] received a nil [ObjectsFunc].
	ErrNilObjectsFunc = errors.New("casbin: objects func must not be nil")

	// ErrNilActionFunc means [WithAction] received a nil [ActionFunc].
	ErrNilActionFunc = errors.New("casbin: action func must not be nil")
)

// SubjectsFunc derives the Casbin subjects from the request identity.
type SubjectsFunc func(r *authz.Request) []string

// ObjectsFunc derives the Casbin objects for a request. An empty result denies.
type ObjectsFunc func(r *authz.Request) []string

// ActionFunc derives the Casbin action for a request.
type ActionFunc func(r *authz.Request) string

// Option configures an [Enforcer].
type Option func(*Enforcer)

// WithObjects replaces the default object derivation (the procedure as the single object).
func WithObjects(fn ObjectsFunc) Option {
	return func(e *Enforcer) {
		e.objects = fn
	}
}

// WithAction replaces the default action, "execute".
func WithAction(fn ActionFunc) Option {
	return func(e *Enforcer) {
		e.action = fn
	}
}

// Enforcer is a Casbin [authz.Enforcer]. Every object must have at least one allowed subject.
type Enforcer struct {
	engine   casbinv2.IEnforcer
	subjects SubjectsFunc
	objects  ObjectsFunc
	action   ActionFunc
}

var _ authz.Enforcer = (*Enforcer)(nil)

// New wraps an existing Casbin engine.
func New(engine casbinv2.IEnforcer, subjects SubjectsFunc, opts ...Option) (*Enforcer, error) {
	if engine == nil {
		return nil, ErrNilEngine
	}
	if subjects == nil {
		return nil, ErrNilSubjectsFunc
	}
	e := &Enforcer{
		engine:   engine,
		subjects: subjects,
		objects:  func(r *authz.Request) []string { return []string{r.Spec.Procedure} },
		action:   func(*authz.Request) string { return "execute" },
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.objects == nil {
		return nil, ErrNilObjectsFunc
	}
	if e.action == nil {
		return nil, ErrNilActionFunc
	}
	return e, nil
}

// NewFromString builds a SyncedEnforcer from model and policy text.
func NewFromString(
	modelText, policyText string,
	subjects SubjectsFunc,
	opts ...Option,
) (*Enforcer, error) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("casbin: parse model: %w", err)
	}
	engine, err := casbinv2.NewSyncedEnforcer(m, stringadapter.NewAdapter(policyText))
	if err != nil {
		return nil, fmt.Errorf("casbin: create enforcer: %w", err)
	}
	return New(engine, subjects, opts...)
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
	objects := e.objects(r)
	if len(objects) == 0 {
		return fmt.Errorf("casbin: no objects derived for %s", r.Spec.Procedure)
	}
	action := e.action(r)
	for _, object := range objects {
		allowed := false
		for _, subject := range subjects {
			ok, err := e.engine.Enforce(subject, object, action)
			if err != nil {
				return fmt.Errorf("casbin: enforce object %q: %w", object, err)
			}
			if ok {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("casbin: no policy allows object %q action %q", object, action)
		}
	}
	return nil
}
