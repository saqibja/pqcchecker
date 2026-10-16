COMPOSE := docker compose

.PHONY: all build certs up down smoke clean

all: certs up

build:
	$(COMPOSE) --profile tools --profile clients build

certs: build
	$(COMPOSE) run --rm certgen

up:
	$(COMPOSE) up -d --force-recreate server
	@sleep 1
	@$(COMPOSE) logs server

down:
	$(COMPOSE) down --remove-orphans

# make smoke CLIENT=openssl35 [MODE=server]
CLIENT ?= openssl35
MODE ?=
smoke:
	bash runner/smoke.sh $(CLIENT) $(MODE)

clean: down
	rm -rf certs/out results/*
