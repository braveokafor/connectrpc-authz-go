module github.com/braveokafor/connectrpc-authz-go/examples/bookstore

go 1.27

replace github.com/braveokafor/connectrpc-authz-go => ../..

require (
	connectrpc.com/authn v0.2.0
	connectrpc.com/connect v1.20.0
	connectrpc.com/grpcreflect v1.3.0
	github.com/braveokafor/connectrpc-authz-go v0.0.0-00010101000000-000000000000
	github.com/brianvoe/gofakeit/v7 v7.16.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	golang.org/x/net v0.58.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/bmatcuk/doublestar/v4 v4.10.0 // indirect
	github.com/casbin/casbin/v2 v2.135.0 // indirect
	github.com/casbin/govaluate v1.10.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
