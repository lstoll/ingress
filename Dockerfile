FROM golang:1.17 AS build-env

RUN mkdir -p /src/ingress
WORKDIR /src/ingress

COPY go.mod .
# COPY go.sum .
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go install ./...

FROM scratch
COPY --from=build-env /go/bin/ingress /ingress
ENTRYPOINT ["/ingress]
