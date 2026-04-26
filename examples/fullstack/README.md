# Full-Stack Authorization Example

A complete ConnectRPC service demonstrating JWT authentication + Casbin RBAC authorization using `connectrpc-authz-go`.

## Stack

| Layer | Library |
|-------|---------|
| Transport | `connectrpc.com/connect` (Connect + gRPC + gRPC-Web) |
| Authentication | `connectrpc.com/authn` (JWT bearer token validation) |
| Authorization | `connectrpc-authz-go` (Casbin RBAC + decision logging) |
| JWT | `github.com/golang-jwt/jwt/v5` |

## Service

**DocumentService** with role-based access:

| RPC | admin | editor | viewer |
|-----|-------|--------|--------|
| GetDocument | yes | yes | yes |
| CreateDocument | yes | yes | no |
| DeleteDocument | yes | no | no |

Pre-seeded users: `alice` (admin), `bob` (editor), `charlie` (viewer).

## Setup

```bash
make install   # install buf, protoc-gen-go, protoc-gen-connect-go
make gen       # generate proto code
make run       # start server on :8080
```

## Usage

### Get a token

```bash
# alice (admin)
TOKEN=$(curl -s -X POST localhost:8080/token \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","roles":["admin"]}' | jq -r .token)
```

### curl (Connect protocol)

```bash
# GetDocument
curl -s localhost:8080/document.v1.DocumentService/GetDocument \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"doc-1"}'

# CreateDocument
curl -s localhost:8080/document.v1.DocumentService/CreateDocument \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"My Doc","content":"Hello world"}'

# DeleteDocument
curl -s localhost:8080/document.v1.DocumentService/DeleteDocument \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"doc-1"}'
```

### grpcurl (gRPC protocol)

```bash
# List services
grpcurl -plaintext localhost:8080 list

# GetDocument
grpcurl -plaintext \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"id":"doc-1"}' \
  localhost:8080 document.v1.DocumentService/GetDocument
```

### Rejection: viewer denied write access

```bash
TOKEN=$(curl -s -X POST localhost:8080/token \
  -H 'Content-Type: application/json' \
  -d '{"subject":"charlie","roles":["viewer"]}' | jq -r .token)

curl -s localhost:8080/document.v1.DocumentService/CreateDocument \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Hack","content":"..."}'
# {"code":"permission_denied","message":"permission denied"}

curl -s localhost:8080/document.v1.DocumentService/DeleteDocument \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"doc-1"}'
# {"code":"permission_denied","message":"permission denied"}
```

### Rejection: editor denied admin access

```bash
TOKEN=$(curl -s -X POST localhost:8080/token \
  -H 'Content-Type: application/json' \
  -d '{"subject":"bob","roles":["editor"]}' | jq -r .token)

curl -s localhost:8080/document.v1.DocumentService/DeleteDocument \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"doc-1"}'
# {"code":"permission_denied","message":"permission denied"}
```

### Rejection: no token

```bash
curl -s localhost:8080/document.v1.DocumentService/GetDocument \
  -H 'Content-Type: application/json' \
  -d '{"id":"doc-1"}'
# {"code":"unauthenticated","message":"missing bearer token"}
```

### Rejection: invalid token

```bash
curl -s localhost:8080/document.v1.DocumentService/GetDocument \
  -H "Authorization: Bearer invalid-token" \
  -H 'Content-Type: application/json' \
  -d '{"id":"doc-1"}'
# {"code":"unauthenticated","message":"invalid token: ..."}
```
