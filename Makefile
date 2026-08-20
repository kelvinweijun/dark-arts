GO ?= go

.PHONY: build test vet fmt-check lab-up lab-down lab-ps lab-log clean

build:
	$(GO) build ./...

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l .; echo "gofmt needed" >&2; exit 1)

lab-up:
	docker compose -f lab/docker-compose.yml up -d --wait

lab-down:
	docker compose -f lab/docker-compose.yml down

lab-ps:
	docker compose -f lab/docker-compose.yml ps

lab-log:
	docker compose -f lab/docker-compose.yml logs -f

lab-seg:
	docker network inspect darkarts-net-lan --format '{{range .Containers}}{{.Name}} {{end}}'
	docker network inspect darkarts-net-egress --format '{{range .Containers}}{{.Name}} {{end}}'

clean:
	rm -rf bin
