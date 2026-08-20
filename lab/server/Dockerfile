FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/server ./cmd/server

FROM alpine:3.21
RUN adduser -D -H darkarts && mkdir -p /data && chown darkarts:darkarts /data
COPY --from=build /out/server /usr/local/bin/server
USER darkarts
ENV DARKARTS_STATE_DIR=/data
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/server"]
