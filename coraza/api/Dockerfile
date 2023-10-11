FROM golang:1.20-alpine AS builder

WORKDIR /usr/src/app

COPY go.mod main.go ./
RUN go get -d ./...
RUN go mod download && go mod verify
RUN go build -v -tags=coraza.rule.multiphase_evaluation -o /usr/local/bin/bw-coraza

FROM golang:1.20-alpine

COPY --from=builder --chown=0:0 /usr/local/bin/bw-coraza /usr/local/bin/bw-coraza

RUN addgroup -g 1000 coraza && \
    adduser -h /coraza -g coraza -s /bin/sh -G coraza -D -u 1000 coraza && \
    mkdir -p /var/log/bunkerweb && \
    ln -s /proc/1/fd/1 /var/log/bunkerweb/coraza.log

WORKDIR /coraza

COPY --chown=0:1000 coreruleset ./coreruleset
COPY --chown=0:1000 coraza.conf bunkerweb*.conf ./

VOLUME /rules-before /rules-after

USER coraza:coraza

CMD ["bw-coraza"]
