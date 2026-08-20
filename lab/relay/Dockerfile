FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -o /out/relay ./cmd/relay

FROM alpine:3.21
RUN adduser -D -H darkarts
COPY --from=build /out/relay /usr/local/bin/relay
USER darkarts
EXPOSE 7443
ENTRYPOINT ["/usr/local/bin/relay"]