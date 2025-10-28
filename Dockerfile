FROM golang:1.23-bullseye AS builder
WORKDIR /src

# Copy shared library first
COPY shared/ ./shared/

# Copy service files
COPY ca/go.mod ca/go.sum ./ca/
WORKDIR /src/ca
RUN go mod download

WORKDIR /src
COPY ca/ ./ca/
WORKDIR /src/ca
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/ca ./cmd/ca

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/ca /usr/local/bin/ca
COPY ca/config/ /config/
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/ca"]

