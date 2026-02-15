# SIEM-SOAR Platform Makefile
# Root build orchestration for all components

.PHONY: all build test lint clean help
.PHONY: go-build go-test go-lint go-clean
.PHONY: py-build py-test py-lint py-clean
.PHONY: web-build web-test web-lint web-clean
.PHONY: docker-build docker-push docker-clean
.PHONY: infra-init infra-plan infra-apply infra-destroy
.PHONY: dev dev-services dev-stop
.PHONY: install pre-commit

# Variables
GO_SERVICES := gateway detection soar ti query case collector pipeline
PYTHON_SERVICES := triage copilot agentic
DOCKER_REGISTRY ?= ghcr.io/siem-soar-platform
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go settings
GO := go
GOFLAGS := -v
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.CommitSHA=$(COMMIT_SHA)"

# Python settings
PYTHON := python3
UV := uv
PYTEST := pytest

# Default target
all: lint test build

#------------------------------------------------------------------------------
# Help
#------------------------------------------------------------------------------
help:
	@echo "SIEM-SOAR Platform Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  all          - Run lint, test, and build"
	@echo "  build        - Build all components"
	@echo "  test         - Run all tests"
	@echo "  lint         - Run all linters"
	@echo "  clean        - Clean all build artifacts"
	@echo ""
	@echo "Go targets:"
	@echo "  go-build     - Build all Go services"
	@echo "  go-test      - Run Go tests"
	@echo "  go-lint      - Run Go linter"
	@echo "  go-clean     - Clean Go build artifacts"
	@echo ""
	@echo "Python targets:"
	@echo "  py-build     - Build Python packages"
	@echo "  py-test      - Run Python tests"
	@echo "  py-lint      - Run Python linter"
	@echo "  py-clean     - Clean Python artifacts"
	@echo ""
	@echo "Web targets:"
	@echo "  web-build    - Build web application"
	@echo "  web-test     - Run web tests"
	@echo "  web-lint     - Run web linter"
	@echo "  web-clean    - Clean web build artifacts"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker-build - Build all Docker images"
	@echo "  docker-push  - Push images to registry"
	@echo "  docker-clean - Remove local images"
	@echo ""
	@echo "Infrastructure targets:"
	@echo "  infra-init   - Initialize Terraform"
	@echo "  infra-plan   - Plan infrastructure changes"
	@echo "  infra-apply  - Apply infrastructure changes"
	@echo "  infra-destroy- Destroy infrastructure"
	@echo ""
	@echo "Development targets:"
	@echo "  dev          - Start full development environment"
	@echo "  dev-up       - Start infrastructure (Docker)"
	@echo "  dev-down     - Stop infrastructure"
	@echo "  dev-reset    - Reset infrastructure (clean volumes)"
	@echo "  dev-logs     - View infrastructure logs"
	@echo "  dev-ps       - Show running containers"
	@echo "  install      - Install all dependencies"
	@echo "  pre-commit   - Install pre-commit hooks"
	@echo ""
	@echo "Service runners:"
	@echo "  run-gateway     - Run API Gateway"
	@echo "  run-detection   - Run Detection Engine"
	@echo "  run-soar        - Run SOAR Engine"
	@echo "  run-query       - Run Query Service"
	@echo "  run-collector   - Run Collector"
	@echo "  run-ai-triage   - Run AI Triage (port 8001)"
	@echo "  run-ai-copilot  - Run AI Copilot (port 8002)"
	@echo "  run-ai-agentic  - Run AI Agentic (port 8003)"
	@echo "  run-frontend    - Run Frontend (port 3000)"
	@echo ""
	@echo "Database targets:"
	@echo "  db-migrate      - Run PostgreSQL migrations"
	@echo "  db-migrate-down - Rollback last migration"
	@echo "  db-migrate-reset- Reset database"
	@echo "  db-clickhouse-init - Initialize ClickHouse schemas"
	@echo ""
	@echo "Test targets:"
	@echo "  test-integration - Run integration tests"
	@echo "  test-e2e        - Run E2E tests"
	@echo "  test-performance- Run performance tests (k6)"

#------------------------------------------------------------------------------
# Install & Setup
#------------------------------------------------------------------------------
install: install-go install-python install-node
	@echo "All dependencies installed"

install-go:
	@echo "Downloading Go dependencies..."
	@for svc in $(GO_SERVICES); do \
		echo "  - services/$$svc"; \
		cd services/$$svc && $(GO) mod download && cd ../..; \
	done

install-python:
	@echo "Installing Python dependencies..."
	cd ai && $(UV) sync

install-node:
	@echo "Installing Node.js dependencies..."
	pnpm install

pre-commit:
	@echo "Installing pre-commit hooks..."
	pre-commit install
	pre-commit install --hook-type commit-msg

#------------------------------------------------------------------------------
# Go Targets
#------------------------------------------------------------------------------
go-build:
	@echo "Building Go services..."
	@for svc in $(GO_SERVICES); do \
		echo "  Building $$svc..."; \
		cd services/$$svc && $(GO) build $(GOFLAGS) $(LDFLAGS) -o ../../bin/$$svc . && cd ../..; \
	done
	@echo "Go services built successfully"

go-test:
	@echo "Running Go tests..."
	@for svc in $(GO_SERVICES); do \
		echo "  Testing $$svc..."; \
		cd services/$$svc && $(GO) test -v -race -coverprofile=coverage.out ./... && cd ../..; \
	done

go-lint:
	@echo "Linting Go code..."
	@for svc in $(GO_SERVICES); do \
		echo "  Linting $$svc..."; \
		cd services/$$svc && golangci-lint run ./... && cd ../..; \
	done

go-clean:
	@echo "Cleaning Go artifacts..."
	rm -rf bin/
	@for svc in $(GO_SERVICES); do \
		rm -f services/$$svc/coverage.out; \
	done

#------------------------------------------------------------------------------
# Python Targets
#------------------------------------------------------------------------------
py-build:
	@echo "Building Python packages..."
	cd ai && $(UV) build

py-test:
	@echo "Running Python tests..."
	cd ai && $(UV) run $(PYTEST) tests/ -v --cov=. --cov-report=term-missing

py-lint:
	@echo "Linting Python code..."
	cd ai && $(UV) run ruff check .
	cd ai && $(UV) run ruff format --check .
	cd ai && $(UV) run mypy .

py-clean:
	@echo "Cleaning Python artifacts..."
	cd ai && rm -rf dist/ build/ *.egg-info/
	find ai -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find ai -type f -name "*.pyc" -delete 2>/dev/null || true

#------------------------------------------------------------------------------
# Web Targets
#------------------------------------------------------------------------------
web-build:
	@echo "Building web application..."
	pnpm turbo run build --filter=web/*

web-test:
	@echo "Running web tests..."
	pnpm turbo run test --filter=web/*

web-lint:
	@echo "Linting web code..."
	pnpm turbo run lint --filter=web/*
	pnpm turbo run typecheck --filter=web/*

web-clean:
	@echo "Cleaning web artifacts..."
	pnpm turbo run clean --filter=web/*
	rm -rf web/*/dist web/*/.next

#------------------------------------------------------------------------------
# Combined Targets
#------------------------------------------------------------------------------
build: go-build py-build web-build
	@echo "All components built successfully"

test: go-test py-test web-test
	@echo "All tests passed"

lint: go-lint py-lint web-lint
	@echo "All linting passed"

clean: go-clean py-clean web-clean docker-clean
	@echo "All artifacts cleaned"

#------------------------------------------------------------------------------
# Docker Targets
#------------------------------------------------------------------------------
docker-build:
	@echo "Building Docker images..."
	@for svc in $(GO_SERVICES); do \
		echo "  Building $$svc image..."; \
		docker build -t $(DOCKER_REGISTRY)/$$svc:$(VERSION) -f services/$$svc/Dockerfile services/$$svc; \
	done
	@for svc in $(PYTHON_SERVICES); do \
		echo "  Building ai-$$svc image..."; \
		docker build -t $(DOCKER_REGISTRY)/ai-$$svc:$(VERSION) -f ai/services/$$svc/Dockerfile ai; \
	done

docker-push:
	@echo "Pushing Docker images..."
	@for svc in $(GO_SERVICES); do \
		docker push $(DOCKER_REGISTRY)/$$svc:$(VERSION); \
	done
	@for svc in $(PYTHON_SERVICES); do \
		docker push $(DOCKER_REGISTRY)/ai-$$svc:$(VERSION); \
	done

docker-clean:
	@echo "Cleaning Docker images..."
	docker image prune -f
	@for svc in $(GO_SERVICES); do \
		docker rmi $(DOCKER_REGISTRY)/$$svc:$(VERSION) 2>/dev/null || true; \
	done
	@for svc in $(PYTHON_SERVICES); do \
		docker rmi $(DOCKER_REGISTRY)/ai-$$svc:$(VERSION) 2>/dev/null || true; \
	done

#------------------------------------------------------------------------------
# Infrastructure Targets
#------------------------------------------------------------------------------
infra-init:
	@echo "Initializing Terraform..."
	cd infra/terraform && terraform init

infra-plan:
	@echo "Planning infrastructure changes..."
	cd infra/terraform && terraform plan -out=tfplan

infra-apply:
	@echo "Applying infrastructure changes..."
	cd infra/terraform && terraform apply tfplan

infra-destroy:
	@echo "Destroying infrastructure..."
	cd infra/terraform && terraform destroy

#------------------------------------------------------------------------------
# Development Targets
#------------------------------------------------------------------------------
dev: dev-up
	@echo "Development environment ready!"
	@echo "Services: http://localhost:8080 (Gateway)"
	@echo "Frontend: http://localhost:3000"
	@echo "Grafana:  http://localhost:3030"
	@echo "Temporal: http://localhost:8088"

dev-up:
	@echo "Starting development infrastructure..."
	docker compose -f docker-compose.dev.yml up -d
	@echo "Waiting for services to be healthy..."
	@sleep 10
	@echo "Running database migrations..."
	@-migrate -path infra/postgres/migrations \
		-database "postgres://siem:siem_dev_password@localhost:5432/siem?sslmode=disable" up 2>/dev/null || true
	@echo "Infrastructure ready!"

dev-down:
	@echo "Stopping development infrastructure..."
	docker compose -f docker-compose.dev.yml down

dev-reset:
	@echo "Resetting development environment..."
	docker compose -f docker-compose.dev.yml down -v
	docker compose -f docker-compose.dev.yml up -d
	@sleep 10
	@-migrate -path infra/postgres/migrations \
		-database "postgres://siem:siem_dev_password@localhost:5432/siem?sslmode=disable" up 2>/dev/null || true

dev-logs:
	docker compose -f docker-compose.dev.yml logs -f

dev-ps:
	docker compose -f docker-compose.dev.yml ps

# Individual service runners
run-gateway:
	cd services/gateway && $(GO) run main.go

run-detection:
	cd services/detection && $(GO) run main.go

run-soar:
	cd services/soar && $(GO) run main.go

run-query:
	cd services/query && $(GO) run main.go

run-collector:
	cd services/collector && $(GO) run main.go

run-ai-triage:
	cd ai && poetry run uvicorn services.triage.main:app --reload --port 8001

run-ai-copilot:
	cd ai && poetry run uvicorn services.copilot.main:app --reload --port 8002

run-ai-agentic:
	cd ai && poetry run uvicorn services.agentic.main:app --reload --port 8003

run-frontend:
	cd web/dashboard && pnpm dev

#------------------------------------------------------------------------------
# Database Targets
#------------------------------------------------------------------------------
db-migrate:
	@echo "Running database migrations..."
	migrate -path infra/postgres/migrations \
		-database "postgres://siem:siem_dev_password@localhost:5432/siem?sslmode=disable" up

db-migrate-down:
	@echo "Rolling back last migration..."
	migrate -path infra/postgres/migrations \
		-database "postgres://siem:siem_dev_password@localhost:5432/siem?sslmode=disable" down 1

db-migrate-reset:
	@echo "Resetting database..."
	migrate -path infra/postgres/migrations \
		-database "postgres://siem:siem_dev_password@localhost:5432/siem?sslmode=disable" drop -f
	migrate -path infra/postgres/migrations \
		-database "postgres://siem:siem_dev_password@localhost:5432/siem?sslmode=disable" up

db-clickhouse-init:
	@echo "Initializing ClickHouse schemas..."
	docker exec -i siem-clickhouse-dev clickhouse-client \
		--user siem --password siem_dev_password < infra/clickhouse/schemas/001_events.sql
	docker exec -i siem-clickhouse-dev clickhouse-client \
		--user siem --password siem_dev_password < infra/clickhouse/schemas/002_alerts.sql
	docker exec -i siem-clickhouse-dev clickhouse-client \
		--user siem --password siem_dev_password < infra/clickhouse/schemas/003_metrics.sql

#------------------------------------------------------------------------------
# Integration Test Targets
#------------------------------------------------------------------------------
test-integration:
	@echo "Running integration tests..."
	cd tests/integration/go && $(GO) test -v -tags=integration ./...
	cd tests/integration/python && poetry run pytest -v

test-e2e:
	@echo "Running E2E tests..."
	cd tests/integration/e2e && poetry run pytest -v

test-performance:
	@echo "Running performance tests..."
	k6 run tests/performance/k6/load_test.js
