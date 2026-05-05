SHELL := /bin/bash

APP_NAME ?= idp-server
BIN_DIR ?= bin
BIN_PATH ?= $(BIN_DIR)/$(APP_NAME)
MAIN_PKG ?= ./cmd/idp

GO ?= go
GOFMT ?= gofmt

LISTEN_ADDR ?= :8080
ISSUER ?= http://localhost:8080
APP_ENV ?= dev
SESSION_TTL ?= 8h

MYSQL_HOST ?= db
MYSQL_PORT ?= 3306
MYSQL_DATABASE ?= app
MYSQL_USER ?= app
MYSQL_PASSWORD ?= ChangeThisAppPassword_32CharsMin

REDIS_HOST ?= redis
REDIS_PORT ?= 6379
REDIS_DB ?= 0

DOCKER ?= docker
DOCKERFILE ?= dockerfile.server
IMAGE ?= $(APP_NAME):latest
COMPOSE ?= docker compose
COMPOSE_FILE ?=
MYSQL_CONTAINER ?= idp-db

MYSQL_CMD = mysql -h $(MYSQL_HOST) -P $(MYSQL_PORT) -u$(MYSQL_USER) -p$(MYSQL_PASSWORD) $(MYSQL_DATABASE)

.PHONY: help build run test fmt clean migrate migrate-docker env docker-build up down logs

help:
	@echo "Available targets:"
	@echo "  make build           Build $(APP_NAME) into $(BIN_PATH)"
	@echo "  make run             Run the IdP with current env vars"
	@echo "  make test            Run go test ./..."
	@echo "  make fmt             Run gofmt on all Go files"
	@echo "  make clean           Remove build output"
	@echo "  make migrate         Apply scripts/migrate.sql using local mysql client"
	@echo "  make migrate-docker  Apply scripts/migrate.sql via docker exec into MYSQL_CONTAINER"
	@echo "  make env             Print effective runtime configuration"
	@echo "  make docker-build    Build Docker image using $(DOCKERFILE)"
	@echo "  make up              Start services via docker compose"
	@echo "  make down            Stop services via docker compose"
	@echo "  make logs            Tail services via docker compose"

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_PATH) $(MAIN_PKG)

run:
	LISTEN_ADDR='$(LISTEN_ADDR)' \
	ISSUER='$(ISSUER)' \
	APP_ENV='$(APP_ENV)' \
	SESSION_TTL='$(SESSION_TTL)' \
	MYSQL_HOST='$(MYSQL_HOST)' \
	MYSQL_PORT='$(MYSQL_PORT)' \
	MYSQL_DATABASE='$(MYSQL_DATABASE)' \
	MYSQL_USER='$(MYSQL_USER)' \
	MYSQL_PASSWORD='$(MYSQL_PASSWORD)' \
	REDIS_HOST='$(REDIS_HOST)' \
	REDIS_PORT='$(REDIS_PORT)' \
	REDIS_DB='$(REDIS_DB)' \
	$(GO) run $(MAIN_PKG)

test:
	$(GO) test ./...

fmt:
	@files="$$(find . -name '*.go' -not -path './vendor/*')"; \
	if [[ -n "$$files" ]]; then \
		$(GOFMT) -w $$files; \
	fi

clean:
	rm -rf $(BIN_DIR)

migrate:
	$(MYSQL_CMD) < scripts/migrate.sql

migrate-docker:
	$(DOCKER) exec -i $(MYSQL_CONTAINER) mysql -u$(MYSQL_USER) -p$(MYSQL_PASSWORD) $(MYSQL_DATABASE) < scripts/migrate.sql

env:
	@echo "APP_NAME=$(APP_NAME)"
	@echo "BIN_PATH=$(BIN_PATH)"
	@echo "LISTEN_ADDR=$(LISTEN_ADDR)"
	@echo "ISSUER=$(ISSUER)"
	@echo "APP_ENV=$(APP_ENV)"
	@echo "SESSION_TTL=$(SESSION_TTL)"
	@echo "MYSQL_HOST=$(MYSQL_HOST)"
	@echo "MYSQL_PORT=$(MYSQL_PORT)"
	@echo "MYSQL_DATABASE=$(MYSQL_DATABASE)"
	@echo "MYSQL_USER=$(MYSQL_USER)"
	@echo "MYSQL_CONTAINER=$(MYSQL_CONTAINER)"
	@echo "REDIS_HOST=$(REDIS_HOST)"
	@echo "REDIS_PORT=$(REDIS_PORT)"
	@echo "REDIS_DB=$(REDIS_DB)"
	@echo "DOCKERFILE=$(DOCKERFILE)"
	@echo "IMAGE=$(IMAGE)"
	@echo "COMPOSE_FILE=$(COMPOSE_FILE)"

docker-build:
	$(DOCKER) build -f $(DOCKERFILE) -t $(IMAGE) .

up:
	@if [[ -n "$(COMPOSE_FILE)" ]]; then \
		$(COMPOSE) -f $(COMPOSE_FILE) up -d; \
	else \
		$(COMPOSE) up -d; \
	fi

down:
	@if [[ -n "$(COMPOSE_FILE)" ]]; then \
		$(COMPOSE) -f $(COMPOSE_FILE) down; \
	else \
		$(COMPOSE) down; \
	fi

logs:
	@if [[ -n "$(COMPOSE_FILE)" ]]; then \
		$(COMPOSE) -f $(COMPOSE_FILE) logs -f; \
	else \
		$(COMPOSE) logs -f; \
	fi
