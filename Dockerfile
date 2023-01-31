FROM golang:1.19 AS builder
WORKDIR /usr/src/app
COPY src/ .
RUN CGO_ENABLED=0 make

FROM alpine:latest
ENTRYPOINT ["/bin/sh", "-c"]
WORKDIR /app
COPY --from=builder /usr/src/app/ganted ./
ENV GANTED_LISTEN=:6626 \
    RADIUS_SERVER=light-freeradius:1812 \
    RADIUS_SECRET=testing123 \
    GANTED_ACL=192.0.2.0/24,198.51.100.0/24,203.0.113.0/24,2001:db8::/32
CMD exec ./ganted -l "$GANTED_LISTEN" -r "$RADIUS_SERVER" -s "$RADIUS_SECRET" -a "$GANTED_ACL"
