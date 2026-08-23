# Bookstore: a Casbin authorisation example

The example runs a ConnectRPC service that authorises unary and streaming RPCs from one Casbin policy. Authentication uses a minimal dev signer.

`BookstoreService` has every RPC kind:

| RPC | Kind | viewer | clerk | admin | bidder |
|-----|------|:---:|:---:|:---:|:---:|
| GetBook / ListBooks | unary | ✓ | ✓ | ✓ | |
| CreateBook | unary | | ✓ | ✓ | |
| ImportBooks | client-stream | | ✓ | ✓ | |
| DeleteBook | unary | | | ✓ | |
| WatchAuction | server-stream | ✓ | ✓ | ✓ | ✓ |
| Bid | bidi-stream | | | | ✓ |

Roles inherit: `admin` > `clerk` > `viewer`. `bidder` is separate. The users are `alice` (admin), `bob` (clerk), `carol` (viewer), and `dave` (bidder).

## The authorisation code

The authorisation needs a policy file and one function. The function names the Casbin subject:

```go
func newEnforcer() (authz.Enforcer, error) {
	return authzcasbin.NewFromString(modelConf, policyCSV, subjects)
}

func subjects(r *authz.Request) []string {
	if id, ok := r.Identity.(*Identity); ok && id != nil {
		return []string{id.Subject}
	}
	return nil
}
```

The object is the RPC procedure. Roles, inheritance, and patterns are in [`policy.csv`](policies/policy.csv). See [`authz.go`](authz.go) and [`main.go`](main.go).

## Run

```bash
make gen      # generate the proto code
make run      # start the server on :8080
```

Create a dev token for each user:

```bash
ALICE=$(go run . -token alice)
CAROL=$(go run . -token carol)
DAVE=$(go run . -token dave)
```

## Unary (curl, Connect protocol)

```bash
# viewer reads a book
curl -s localhost:8080/bookstore.v1.BookstoreService/GetBook \
  -H "Authorization: Bearer $CAROL" -H 'Content-Type: application/json' -d '{"id":1}'

# viewer cannot create
curl -s localhost:8080/bookstore.v1.BookstoreService/CreateBook \
  -H "Authorization: Bearer $CAROL" -H 'Content-Type: application/json' \
  -d '{"title":"Dune","author":"Herbert","shelf":1}'
# {"code":"permission_denied","message":"permission denied"}

# no token
curl -s localhost:8080/bookstore.v1.BookstoreService/GetBook \
  -H 'Content-Type: application/json' -d '{"id":1}'
# {"code":"unauthenticated","message":"missing bearer token"}
```

## Streaming (grpcurl, gRPC protocol)

The interceptor authorises a stream one time, when it opens, on identity and role.

```bash
# bidder places a bid (bidi)
grpcurl -plaintext -H "Authorization: Bearer $DAVE" \
  -d '{"book":1,"amount":50}' localhost:8080 bookstore.v1.BookstoreService/Bid

# viewer cannot bid
grpcurl -plaintext -H "Authorization: Bearer $CAROL" \
  -d '{"book":1,"amount":50}' localhost:8080 bookstore.v1.BookstoreService/Bid
# ERROR: Code: PermissionDenied
```
