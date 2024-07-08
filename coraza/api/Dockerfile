FROM golang:1.22-alpine@sha256:8c9183f715b0b4eca05b8b3dbf59766aaedb41ec07477b132ee2891ac0110a07 AS builder

WORKDIR /usr/src/app

COPY go.mod main.go ./
RUN go get -d ./...
RUN go mod download && go mod verify
RUN go build -v -tags=coraza.rule.multiphase_evaluation -o /usr/local/bin/bw-coraza

COPY --chmod=644 crs.sh .
RUN apk add bash git && \
    bash crs.sh Download

FROM golang:1.22-alpine@sha256:8c9183f715b0b4eca05b8b3dbf59766aaedb41ec07477b132ee2891ac0110a07

COPY --from=builder --chown=0:0 /usr/local/bin/bw-coraza /usr/local/bin/bw-coraza

RUN apk add --no-cache bash curl && \
    addgroup -g 1000 coraza && \
    adduser -h /usr/share/coraza -g coraza -s /bin/bash -G coraza -D -u 1000 coraza && \
    mkdir -p /var/log/coraza /var/run/coraza && \
    chown root:coraza /var/log/coraza /var/run/coraza && \
    chmod 770 /var/log/coraza /var/run/coraza && \
    ln -s /proc/1/fd/1 /var/log/coraza/coraza.log

WORKDIR /usr/share/coraza

COPY --from=builder --chown=0:1000 /usr/src/app/coreruleset ./coreruleset
COPY --chown=0:1000 coraza.conf bunkerweb*.conf ./
COPY --chown=0:1000 --chmod=750 healthcheck.sh ./

# Fix CVEs
RUN apk add --no-cache "libcrypto3>=3.3.1-r1" "libssl3>=3.3.1-r1" # CVE-2024-5535

VOLUME /rules-before /rules-after

EXPOSE 8080

USER coraza:coraza

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=6 CMD /usr/share/coraza/healthcheck.sh

CMD ["bw-coraza"]
