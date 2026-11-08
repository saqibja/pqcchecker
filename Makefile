COMPOSE := docker compose

.PHONY: all build certs up down run report clean

all: certs up run report

build:
	$(COMPOSE) --profile tools --profile clients build

# Every round reuses the same chains so results stay comparable. Regenerating them starts a new
# baseline: make certs FORCE=1
certs: build
	@if [ -e certs/out ] && [ "$(FORCE)" != 1 ]; then \
	  echo "certs/out exists; keeping it (the study's chains). make certs FORCE=1 regenerates."; \
	else $(COMPOSE) run --rm certgen; fi

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
