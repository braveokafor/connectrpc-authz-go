// Copyright (c) 2025-2026 Brave Okafor
// SPDX-License-Identifier: MIT

// Package authz provides authorisation interceptors for ConnectRPC.
//
// [Enforcer] is the one-method decision contract, and the casbin subpackage is one implementation.
// Connect decodes a unary RPC before authz, so add authentication first.
package authz
