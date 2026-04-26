.PHONY: all
all: install gen build

.PHONY: clean
clean:
	rm -rf ./gen

.PHONY: install
install:
	@ echo ":: Installing tools"
	go install github.com/bufbuild/buf/cmd/buf@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest
	@ echo ":: Tidying modules"
	go mod tidy

.PHONY: gen
gen: clean
	@ echo ":: Running buf generate"
	buf lint
	buf format -w
	buf build
	buf generate

.PHONY: build
build:
	go build -o bin/server .

.PHONY: run
run:
	go run .
