COMPOSE := docker compose

.PHONY: all build certs up down run report clean

all: certs up run report

build:
	$(COMPOSE) --profile tools --profile clients build

certs: build
	$(COMPOSE) run --rm certgen

up:
	$(COMPOSE) up -d --force-recreate server
	@sleep 1
	@$(COMPOSE) logs server | grep -E 'Server stack|listening'

down:
	$(COMPOSE) down --remove-orphans

# make run [CLIENTS="go chrome"]
CLIENTS ?=
run: build
	python3 runner/run.py $(CLIENTS)

report:
	python3 runner/report.py

clean: down
	rm -rf certs/out results/runs results/results.csv results/negative_controls.csv \
		results/meta.json results/report.html
