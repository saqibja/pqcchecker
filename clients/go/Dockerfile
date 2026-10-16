# Go crypto/tls client. Build context: ./clients
FROM golang:1.27.2-trixie@sha256:47667934874913a449b96faa7ef4777fa285d9ec29126ee80ed61c45b7cccf0e

WORKDIR /src
COPY go/go.mod go/main.go ./
RUN CGO_ENABLED=0 go build -o /usr/local/bin/pqcc-client .
