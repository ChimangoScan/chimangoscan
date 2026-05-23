.PHONY: build clean init start stop update logs status

# Detects docker-compose v1 or v2 automatically
DOCKER_COMPOSE := $(shell command -v docker-compose >/dev/null 2>&1 && echo docker-compose || echo "docker compose")

BINARY = ditector

# ── Local build ───────────────────────────────────────────────────────────────
build:
	@GOARCH=amd64 go build -o $(BINARY)

clean:
	@rm -f $(BINARY)

rebuild: clean build

# ── Configuration: reads .env if present ──────────────────────────────────────
-include .env
export

ifeq ($(ROLE),secondary)
  _MONGO    := mongodb://$(DB_HOST):27017
  _NEO4J    := neo4j://$(DB_HOST):7687
  _PROFILES :=
else
  _MONGO    := mongodb://localhost:27017
  _NEO4J    := neo4j://localhost:7687
  _PROFILES := --profile db
endif

# ── Operation ───────────────────────────────────────────────────────────────────
init:
	@[ -f .env ] && echo ".env already exists." || (cp .env.example .env && echo "Created .env — edit it before continuing.")

start:
	@[ -f .env ] || (echo "Run 'make init' first." && exit 1)
	-$(DOCKER_COMPOSE) $(_PROFILES) -p ditector-crawler rm -fs crawler $(if $(_PROFILES),mongodb neo4j,) 2>/dev/null
	MONGO_URI=$(_MONGO) NEO4J_URI=$(_NEO4J) \
	  $(DOCKER_COMPOSE) $(_PROFILES) -p ditector-crawler up -d crawler \
	  $(if $(_PROFILES),mongodb neo4j,)

stop:
	$(DOCKER_COMPOSE) $(_PROFILES) -p ditector-crawler stop

stop-build:
	$(DOCKER_COMPOSE) -f docker-compose.node3.yml -p ditector-builder stop

clean-containers:
	@echo "Cleaning up the project's stale containers..."
	@docker ps -a | grep ditector | awk '{print $$1}' | xargs -r docker rm -f

update:
	git fetch origin master && git reset --hard origin/master
	@$(MAKE) start

start-build:
	@[ -f .env ] || (echo "Run 'make init' first." && exit 1)
	-$(DOCKER_COMPOSE) -f docker-compose.node3.yml -p ditector-builder rm -fs builder 2>/dev/null
	MONGO_URI=$(_MONGO) NEO4J_URI=$(_NEO4J) \
	  $(DOCKER_COMPOSE) -f docker-compose.node3.yml -p ditector-builder up -d builder

logs:
	@docker logs -f ditector_crawler 2>&1 | grep -E "Flushed|WARN|ERROR|401|429"

logs-build:
	@docker logs -f ditector_builder 2>&1

status:
	@mongosh $(_MONGO)/dockerhub_data --quiet --eval \
	  'print("repos:", db.repositories_data.countDocuments(), \
	         " | keywords:", db.crawler_keywords.countDocuments(), \
	         " | graph_built:", db.repositories_data.countDocuments({graph_built_at:{$$exists:true}}))'
