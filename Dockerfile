FROM golang:1.19 AS builder
WORKDIR /usr/src/app
COPY src/ .
RUN CGO_ENABLED=0 make

FROM alpine:latest
WORKDIR /app
COPY --from=builder /usr/src/app/ganted ./
COPY start.sh ./
CMD ["/app/start.sh"]
