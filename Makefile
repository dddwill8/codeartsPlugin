PLUGIN_ID := codearts
GOIMAGE ?= golang:1.26-bookworm
CPA_IMAGE ?= eceasy/cli-proxy-api:v8.0.44
GOPROXY ?= https://goproxy.cn,direct
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
HOST_ARCH := amd64
else ifeq ($(UNAME_M),amd64)
HOST_ARCH := amd64
else ifeq ($(UNAME_M),aarch64)
HOST_ARCH := arm64
else
HOST_ARCH := arm64
endif
PLATFORM ?= linux/$(HOST_ARCH)
PLUGIN_ARCH := $(notdir $(PLATFORM))
PLUGIN_DIR := plugins/linux/$(PLUGIN_ARCH)
PLUGIN_SO := $(PLUGIN_DIR)/$(PLUGIN_ID).so
PANEL_HTML := deploy/cpa/panel/management.html
PANEL_REPO ?= router-for-me/Cli-Proxy-API-Management-Center
DOCKER_GO = docker run --rm --platform $(PLATFORM) \
	-e CGO_ENABLED=1 \
	-e GOPROXY=$(GOPROXY) \
	-e GOFLAGS=-buildvcs=false \
	-v "$(CURDIR)":/src -w /src \
	-v codearts-gomod:/go/pkg/mod \
	-v codearts-gocache:/root/.cache/go-build \
	$(GOIMAGE)

.PHONY: test test2 plugin tidy panel compose-up compose-down verify

tidy:
	$(DOCKER_GO) bash -c 'apt-get update -qq && apt-get install -y -qq gcc >/dev/null && go mod tidy'

test:
	$(DOCKER_GO) bash -c 'apt-get update -qq && apt-get install -y -qq gcc >/dev/null && go test ./internal/...'

test2: test

plugin:
	mkdir -p $(PLUGIN_DIR)
	$(DOCKER_GO) bash -c 'apt-get update -qq && apt-get install -y -qq gcc >/dev/null && go build -buildmode=c-shared -o /src/$(PLUGIN_SO) ./cmd/plugin && rm -f /src/$(PLUGIN_DIR)/$(PLUGIN_ID).h'

panel: $(PANEL_HTML)

$(PANEL_HTML):
	mkdir -p deploy/cpa/panel
	gh release download -R $(PANEL_REPO) -p management.html -D deploy/cpa/panel --clobber

compose-up: plugin panel
	mkdir -p deploy/cpa/auths deploy/cpa/logs deploy/cpa/panel
	CPA_IMAGE=$(CPA_IMAGE) docker compose -f deploy/cpa/docker-compose.yml up -d --force-recreate

compose-down:
	docker compose -f deploy/cpa/docker-compose.yml down --remove-orphans

verify: test plugin
	@echo "run compose-up and GET /v1/models separately"
