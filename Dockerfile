FROM golang:1-alpine AS builder
RUN apk --no-cache add make
WORKDIR /usr/src/app
COPY src/ .
RUN make

FROM alpine:latest
WORKDIR /app
COPY --from=builder /usr/src/app/ganted ./
ENV GANTED_LISTEN=:6626 \
    RADIUS_SERVER=light-freeradius:1812 \
    RADIUS_SECRET=testing123 \
    GANTED_ACL=91.108.4.0/22,91.108.8.0/21,91.108.16.0/21,91.108.36.0/22,91.108.56.0/22,149.154.160.0/20,2001:67c:4e8::/48,2001:b28:f23c::/46 \
    GANTED_BIND_OUTPUT=0.0.0.0 \
    GANTED_AUTH_CACHE_RETENTION=10m \
    GANTED_AUTH_CACHE_GC=10m
CMD ["./ganted"]
