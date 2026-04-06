# syntax=docker/dockerfile:1.3

FROM golang:1-trixie AS build-env

RUN mkdir -p /src/ingress
WORKDIR /src/ingress

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go install ./...

FROM debian:trixie-slim
COPY --from=build-env /go/bin/http-sidecar /
COPY --from=build-env /go/bin/sni-lb /
