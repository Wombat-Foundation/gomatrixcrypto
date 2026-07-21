SHELL := /bin/bash
.DEFAULT_GOAL := help

STYLE_CYAN := $(shell tput setaf 6 2>/dev/null || printf '\033[36m')
STYLE_RESET := $(shell tput sgr0 2>/dev/null || printf '\033[0m')

GO ?= go
STATICCHECK ?= staticcheck
VETFLAGS ?=
STATICCHECKFLAGS ?=
PKGS := ./...
LIBPKGS := $(shell $(GO) list ./... | grep -v '/cmd/')
GOFILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')
COVERPROFILE ?= coverage.out

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z0-9_\/-]+:[[:space:]]*## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":[[:space:]]*## "}; {printf "$(STYLE_CYAN)%-12s$(STYLE_RESET) %s\n", $$1, $$2}'

.PHONY: format
format: ## Format Go source files and run pre-commit hooks
	$(GO) fmt $(PKGS)
	pre-commit run --all-files

.PHONY: test
test: ## Run the test suite (library packages only, excludes cmd/)
	$(GO) test $(LIBPKGS)

.PHONY: _test/all
_test/all: ## Run the test suite for all packages, including cmd/
	$(GO) test $(PKGS)

.PHONY: cov
cov: ## Run tests with coverage and print a summary (library packages only, excludes cmd/)
	$(GO) test -coverprofile=$(COVERPROFILE) $(LIBPKGS)
	$(GO) tool cover -func=$(COVERPROFILE)

.PHONY: _cov/all
_cov/all: ## Run tests with coverage and print a summary for all packages, including cmd/
	$(GO) test -coverprofile=$(COVERPROFILE) $(PKGS)
	$(GO) tool cover -func=$(COVERPROFILE)

.PHONY: lint
lint:	## Run lint checks
	$(GO) vet $(VETFLAGS) $(PKGS)
	$(STATICCHECK) -checks=all $(STATICCHECKFLAGS) $(PKGS)

.PHONY: build
build: ## Compile all packages
	$(GO) build $(PKGS)

.PHONY: tidy
tidy: ## Tidy module dependencies
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove generated coverage and bin artifacts
	rm -f coverage.out cover.out
	rm -rf bin
