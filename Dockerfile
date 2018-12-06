FROM alpine:3.8

RUN apk add --no-cache ca-certificates

USER nobody

COPY tail /usr/local/bin
COPY pkg/handler/login.html /var/tmp
