// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

package authz

import (
	"errors"
	"fmt"

	"connectrpc.com/connect"
)

var (
	// ErrNilIdentityFunc is returned when a nil IdentityFunc is passed to [NewInterceptor].
	ErrNilIdentityFunc = errors.New("authz: getIdentity must not be nil")

	// ErrNilEnforcer is returned when a nil [Enforcer] is passed to [NewInterceptor].
	ErrNilEnforcer = errors.New("authz: enforcer must not be nil")

	// ErrNilSubjectExtractor is returned when a nil [SubjectExtractorFunc] is passed
	// to a CasbinEnforcer constructor.
	ErrNilSubjectExtractor = errors.New("authz: subjectExtractor must not be nil")
)

// Errorf returns an error coded with [connect.CodePermissionDenied].
func Errorf(template string, args ...any) *connect.Error {
	return connect.NewError(connect.CodePermissionDenied, fmt.Errorf(template, args...))
}

// ErrorUnauthenticated returns an error coded with [connect.CodeUnauthenticated].
func ErrorUnauthenticated(template string, args ...any) *connect.Error {
	return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf(template, args...))
}
