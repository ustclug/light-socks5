FROM golang:1.19 AS builder
WORKDIR /usr/src/app
COPY src/ .
RUN ls && CGO_ENABLED=0 make

FROM alpine:latest
COPY --from=builder /usr/src/app/ganted ./
CMD ["./ganted"]
