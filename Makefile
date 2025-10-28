.PHONY: build test lint docker run-local migrate clean

build:
	go build -o bin/ca ./cmd/ca

test:
	go test ./... -v

lint:
	golangci-lint run ./...

docker:
	docker build -t gigvault/ca:local .

run-local: docker
	../infra/scripts/deploy-local.sh ca

migrate:
	migrate -path migrations -database $$DATABASE_URL up

clean:
	rm -rf bin/
	go clean

