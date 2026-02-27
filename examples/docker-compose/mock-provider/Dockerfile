FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY main.go .
RUN CGO_ENABLED=0 go build -o mock-provider main.go

FROM alpine:3.20
COPY --from=builder /build/mock-provider /usr/local/bin/mock-provider
EXPOSE 9090
CMD ["mock-provider"]
