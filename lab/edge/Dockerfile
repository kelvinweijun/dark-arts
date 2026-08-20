FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -o /out/edge ./cmd/edge

FROM alpine:3.21
RUN adduser -D -H darkarts
COPY --from=build /out/edge /usr/local/bin/edge
USER darkarts
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/edge"]
