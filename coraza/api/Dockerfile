FROM golang:1.22-alpine@sha256:ace6cc3fe58d0c7b12303c57afe6d6724851152df55e08057b43990b927ad5e8 AS builder

WORKDIR /usr/src/app

COPY go.mod main.go ./
RUN go get -d ./...
RUN go mod download && go mod verify
RUN go build -v -tags=coraza.rule.multiphase_evaluation -o /usr/local/bin/bw-coraza

COPY --chmod=644 crs.sh .
RUN apk add bash git && \
    bash crs.sh Download

FROM golang:1.22-alpine@sha256:ace6cc3fe58d0c7b12303c57afe6d6724851152df55e08057b43990b927ad5e8

COPY --from=builder --chown=0:0 /usr/local/bin/bw-coraza /usr/local/bin/bw-coraza

RUN addgroup -g 1000 coraza && \
    adduser -h /usr/share/coraza -g coraza -s /bin/sh -G coraza -D -u 1000 coraza && \
    mkdir -p /var/log/bunkerweb && \
    ln -s /proc/1/fd/1 /var/log/bunkerweb/coraza.log

WORKDIR /usr/share/coraza

COPY --from=builder --chown=0:1000 /usr/src/app/coreruleset ./coreruleset
COPY --chown=0:1000 coraza.conf bunkerweb*.conf ./

VOLUME /rules-before /rules-after

USER coraza:coraza

CMD ["bw-coraza"]
