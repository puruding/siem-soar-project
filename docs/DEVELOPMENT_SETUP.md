# SIEM-SOAR 개발 환경 구축 가이드

이 문서는 SIEM-SOAR 플랫폼 개발을 위한 로컬 환경 구축 방법을 설명합니다.

---

## 목차

1. [사전 요구사항](#1-사전-요구사항)
2. [데이터베이스 설정](#2-데이터베이스-설정)
3. [메시지 큐 설정 (Kafka)](#3-메시지-큐-설정-kafka)
4. [워크플로우 엔진 (Temporal)](#4-워크플로우-엔진-temporal)
5. [Go 개발 환경](#5-go-개발-환경)
6. [Python AI 개발 환경](#6-python-ai-개발-환경)
7. [Frontend 개발 환경](#7-frontend-개발-환경)
8. [Infrastructure 로컬 설정](#8-infrastructure-로컬-설정)
9. [통합 개발 환경 (Docker Compose)](#9-통합-개발-환경-docker-compose)
10. [서비스 실행](#10-서비스-실행)
11. [테스트 실행](#11-테스트-실행)
12. [트러블슈팅](#12-트러블슈팅)

---

## 1. 사전 요구사항

### 필수 소프트웨어

| 소프트웨어 | 버전 | 용도 |
|-----------|------|------|
| Docker Desktop | 24.0+ | 컨테이너 런타임 |
| Go | 1.21+ | 백엔드 서비스 |
| Python | 3.11+ | AI 서비스 |
| Node.js | 20 LTS | 프론트엔드 |
| pnpm | 8.0+ | 패키지 매니저 |
| Poetry | 1.7+ | Python 패키지 매니저 |
| Make | 4.0+ | 빌드 자동화 |
| Git | 2.40+ | 버전 관리 |

### 설치 확인

```bash
# 버전 확인
docker --version          # Docker version 24.0+
go version                # go1.21+
python --version          # Python 3.11+
node --version            # v20.x
pnpm --version            # 8.x
poetry --version          # Poetry 1.7+
make --version            # GNU Make 4.x
git --version             # git version 2.40+
```

### Windows 추가 설정

```powershell
# WSL2 활성화 (Docker Desktop 필요)
wsl --install

# Go 설치 (Winget)
winget install -e --id GoLang.Go

# Make 설치 (Winget)
winget install -e --id ezwinports.make

# pnpm 설치 (npm 경유)
npm install -g pnpm

# 또는 Git Bash 사용 시 Make 포함됨
```

### macOS 추가 설정

```bash
# Homebrew로 설치
brew install go python@3.11 node pnpm poetry make
```

---

## 2. 데이터베이스 설정

### 2.1 ClickHouse (OLAP - 이벤트 저장소)

#### Docker로 실행

```bash
# 단일 노드 (개발용)
docker run -d \
  --name clickhouse-dev \
  -p 8123:8123 \
  -p 9000:9000 \
  -v clickhouse_data:/var/lib/clickhouse \
  -e CLICKHOUSE_DB=siem \
  -e CLICKHOUSE_USER=siem \
  -e CLICKHOUSE_PASSWORD=siem_dev_password \
  clickhouse/clickhouse-server:24.1

# 접속 테스트
docker exec -it clickhouse-dev clickhouse-client \
  --user siem --password siem_dev_password
```

#### 스키마 초기화

```bash
# 스키마 적용
docker exec -i clickhouse-dev clickhouse-client \
  --user siem --password siem_dev_password \
  < infra/clickhouse/schemas/001_events.sql

docker exec -i clickhouse-dev clickhouse-client \
  --user siem --password siem_dev_password \
  < infra/clickhouse/schemas/002_alerts.sql

docker exec -i clickhouse-dev clickhouse-client \
  --user siem --password siem_dev_password \
  < infra/clickhouse/schemas/003_metrics.sql
```

#### 연결 정보

```yaml
# 환경 변수
CLICKHOUSE_HOST: localhost
CLICKHOUSE_PORT: 9000
CLICKHOUSE_HTTP_PORT: 8123
CLICKHOUSE_DATABASE: siem
CLICKHOUSE_USER: siem
CLICKHOUSE_PASSWORD: siem_dev_password
```

### 2.2 PostgreSQL (OLTP - 메타데이터)

#### Docker로 실행

```bash
docker run -d \
  --name postgres-dev \
  -p 5432:5432 \
  -v postgres_data:/var/lib/postgresql/data \
  -e POSTGRES_DB=siem \
  -e POSTGRES_USER=siem \
  -e POSTGRES_PASSWORD=siem_dev_password \
  postgres:15-alpine

# 접속 테스트
docker exec -it postgres-dev psql -U siem -d siem
```

#### 마이그레이션 실행(데이터베이스 스키마(테이블, 컬럼 등)를 버전 관리하고 자동으로 적용/롤백하는 도구)

##### 팀원마다 DB 스키마 다름동일한 마이그레이션 파일 공유

```bash
# golang-migrate 설치 (로컬)
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# 또는 Docker로 마이그레이션 실행 (로컬 도구 없을 시 권장)
docker run --rm -v "$(pwd)/infra/postgres/migrations:/migrations" --network siem-soar-project_siem-network migrate/migrate -path=/migrations/ -database "postgres://siem:siem_dev_password@siem-postgres-dev:5432/siem?sslmode=disable" up

# 마이그레이션 실행
migrate -path infra/postgres/migrations \
  -database "postgres://siem:siem_dev_password@localhost:5432/siem?sslmode=disable" \
  up

# 롤백 (필요시)
migrate -path infra/postgres/migrations \
  -database "postgres://siem:siem_dev_password@localhost:5432/siem?sslmode=disable" \
  down 1
```

#### 연결 정보

```yaml
POSTGRES_HOST: localhost
POSTGRES_PORT: 5432
POSTGRES_DATABASE: siem
POSTGRES_USER: siem
POSTGRES_PASSWORD: siem_dev_password
POSTGRES_SSLMODE: disable
```

### 2.3 Redis (캐시 & 세션)

#### Docker로 실행

```bash
docker run -d \
  --name redis-dev \
  -p 6379:6379 \
  -v redis_data:/data \
  redis:7-alpine \
  redis-server --appendonly yes --requirepass siem_dev_password

# 접속 테스트
docker exec -it redis-dev redis-cli -a siem_dev_password PING
```

#### 연결 정보

```yaml
REDIS_HOST: localhost
REDIS_PORT: 6379
REDIS_PASSWORD: siem_dev_password
REDIS_DB: 0
```

---

## 3. 메시지 큐 설정 (Kafka)

### 3.1 Docker Compose로 Kafka 클러스터 실행

```bash
cd infra/kafka
docker-compose up -d
```

또는 단일 노드:

```bash
# KRaft 모드 (ZooKeeper 없음)
docker run -d \
  --name kafka-dev \
  -p 9092:9092 \
  -p 9093:9093 \
  -e KAFKA_CFG_NODE_ID=1 \
  -e KAFKA_CFG_PROCESS_ROLES=broker,controller \
  -e KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  -e KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
  -e KAFKA_CFG_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092 \
  -e KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  -e ALLOW_PLAINTEXT_LISTENER=yes \
  bitnamilegacy/kafka:3.6
```

### 3.2 토픽 생성

```bash
# kafka-topics 명령어 사용
docker exec -it kafka-dev kafka-topics.sh --create \
  --bootstrap-server localhost:9092 \
  --topic raw-logs \
  --partitions 8 \
  --replication-factor 1

docker exec -it kafka-dev kafka-topics.sh --create \
  --bootstrap-server localhost:9092 \
  --topic parsed-events \
  --partitions 8 \
  --replication-factor 1

docker exec -it kafka-dev kafka-topics.sh --create \
  --bootstrap-server localhost:9092 \
  --topic normalized-events \
  --partitions 8 \
  --replication-factor 1

docker exec -it kafka-dev kafka-topics.sh --create \
  --bootstrap-server localhost:9092 \
  --topic enriched-events \
  --partitions 8 \
  --replication-factor 1

docker exec -it kafka-dev kafka-topics.sh --create \
  --bootstrap-server localhost:9092 \
  --topic alerts \
  --partitions 8 \
  --replication-factor 1

# 토픽 목록 확인
docker exec -it kafka-dev kafka-topics.sh --list \
  --bootstrap-server localhost:9092
```

### 3.3 연결 정보

```yaml
KAFKA_BOOTSTRAP_SERVERS: localhost:9092
KAFKA_CONSUMER_GROUP: siem-dev
```

### 3.4 테스트

```bash
# Producer 테스트
docker exec -it kafka-dev kafka-console-producer.sh \
  --bootstrap-server localhost:9092 \
  --topic raw-logs

# Consumer 테스트 (다른 터미널)
docker exec -it kafka-dev kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic raw-logs \
  --from-beginning
```

---

## 4. 워크플로우 엔진 (Temporal)

### 4.1 Docker Compose로 실행

```bash
cd infra/temporal
docker-compose up -d
```

또는 단일 명령어:

```bash
# Temporal Server + PostgreSQL
docker run -d \
  --name temporal-dev \
  -p 7233:7233 \
  -p 8088:8088 \
  -e DB=postgresql \
  -e DB_PORT=5432 \
  -e POSTGRES_USER=temporal \
  -e POSTGRES_PWD=temporal_dev \
  -e POSTGRES_SEEDS=host.docker.internal \
  temporalio/auto-setup:1.22

# Temporal Web UI
docker run -d \
  --name temporal-ui-dev \
  -p 8080:8080 \
  -e TEMPORAL_ADDRESS=host.docker.internal:7233 \
  -e TEMPORAL_CORS_ORIGINS=http://localhost:3000 \
  temporalio/ui:2.21
```

### 4.2 네임스페이스 생성

```bash
# Temporal CLI 설치
go install github.com/temporalio/cli/cmd/temporal@latest

# 네임스페이스 생성
temporal operator namespace create siem-soar \
  --address localhost:7233

# 네임스페이스 확인
temporal operator namespace describe siem-soar \
  --address localhost:7233
```

### 4.3 연결 정보

```yaml
TEMPORAL_ADDRESS: localhost:7233
TEMPORAL_NAMESPACE: siem-soar
TEMPORAL_UI_URL: http://localhost:8080
```

### 4.4 Web UI 접속

- **Temporal UI**: http://localhost:8080
- 워크플로우 실행 상태, 히스토리, 태스크 큐 모니터링

---

## 5. Go 개발 환경

### 5.1 Go 설치 및 설정

```bash
# Go 설치 확인
go version

# GOPATH 설정 (선택사항)
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Go 모듈 캐시 정리 (필요시)
go clean -modcache
```

### 5.2 의존성 설치

```bash
# 루트에서 모든 서비스 의존성 설치
cd siem-soar-project

# 개별 서비스 의존성
cd services/gateway && go mod download
cd services/detection && go mod download
cd services/soar && go mod download
cd services/ti && go mod download
cd services/query && go mod download
cd services/case && go mod download
cd services/collector && go mod download
cd services/pipeline && go mod download

# 공통 패키지
cd pkg/config && go mod download
cd pkg/logger && go mod download
cd pkg/repository && go mod download
cd pkg/connector && go mod download
```

### 5.3 개발 도구 설치

```bash
# 린터
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# 코드 생성
go install github.com/golang/mock/mockgen@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# 핫 리로드
go install github.com/cosmtrek/air@latest

# 마이그레이션
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
```

### 5.4 환경 변수 설정

```bash
# .env.local 파일 생성 (각 서비스 디렉토리)
cat > services/gateway/.env.local << 'EOF'
# Server
PORT=8080
ENV=development

# Database
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DATABASE=siem
POSTGRES_USER=siem
POSTGRES_PASSWORD=siem_dev_password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=siem_dev_password

# Kafka
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# JWT
JWT_SECRET=dev-secret-key-change-in-production
JWT_EXPIRY=24h
EOF
```

### 5.5 서비스 실행

```bash
# 직접 실행
cd services/gateway && go run main.go

# Air로 핫 리로드 실행
cd services/gateway && air

# Makefile 사용
make run-gateway
make run-detection
make run-soar
```

### 5.6 빌드

```bash
# 개별 서비스 빌드
cd services/gateway && go build -o bin/gateway main.go

# 전체 빌드
make go-build

# Docker 이미지 빌드
docker build -t siem-gateway:dev -f services/gateway/Dockerfile .
```

---

## 6. Python AI 개발 환경

### 6.1 Python 설치 및 설정

```bash
# pyenv 사용 권장 (버전 관리)
curl https://pyenv.run | bash

# Python 3.11 설치
pyenv install 3.11.9
pyenv local 3.11.9

# 버전 확인
python --version
```

### 6.2 Poetry 설정

```bash
# Poetry 설치
curl -sSL https://install.python-poetry.org | python3 -

# Poetry 설정
poetry config virtualenvs.in-project true  # .venv를 프로젝트 내에 생성
```

### 6.3 의존성 설치

```bash
cd ai

# 의존성 설치
poetry install --no-root

# Windows 호환성 참고:
# - pyproject.toml에서 faiss-gpu 대신 faiss-cpu 사용
# - vllm 등 리눅스 전용 패키지는 주석 처리 필요

# GPU 지원 PyTorch 설치 (CUDA 12.1)
poetry run pip install torch torchvision --index-url https://download.pytorch.org/whl/cu121

# 개발 의존성 포함
poetry install --with dev
```

### 6.4 환경 변수 설정

```bash
# ai/.env 파일 생성
cat > ai/.env << 'EOF'
# Environment
ENV=development
DEBUG=true

# Database
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=9000
CLICKHOUSE_DATABASE=siem
CLICKHOUSE_USER=siem
CLICKHOUSE_PASSWORD=siem_dev_password

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DATABASE=siem
POSTGRES_USER=siem
POSTGRES_PASSWORD=siem_dev_password

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=siem_dev_password

# Kafka
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# AI Models
MODEL_PATH=./models
DEVICE=cpu  # 또는 cuda:0

# LLM
OPENAI_API_KEY=your-api-key  # 개발용
LLM_MODEL=gpt-4  # 또는 로컬 모델

# vLLM (로컬 LLM 서빙)
VLLM_HOST=localhost
VLLM_PORT=8000
EOF
```

### 6.5 서비스 실행

```bash
cd ai

# Alert Triage 서비스
poetry run uvicorn services.triage.main:app --reload --port 8001

# Copilot 서비스
poetry run uvicorn services.copilot.main:app --reload --port 8002

# Agentic AI 서비스
poetry run uvicorn services.agentic.main:app --reload --port 8003
```

### 6.6 Jupyter Notebook (모델 개발)

```bash
cd ai

# Jupyter 설치
poetry add jupyter jupyterlab --group dev

# Jupyter Lab 실행
poetry run jupyter lab --port 8888
```

### 6.7 vLLM 로컬 서빙 (선택사항)

```bash
# vLLM 설치 (GPU 필요)
poetry add vllm

# 모델 서빙
poetry run python -m vllm.entrypoints.openai.api_server \
  --model meta-llama/Llama-2-7b-chat-hf \
  --port 8000 \
  --tensor-parallel-size 1
```

---

## 7. Frontend 개발 환경

### 7.1 Node.js 및 pnpm 설치

```bash
# Node.js 설치 (nvm 권장)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 20
nvm use 20

# pnpm 설치
npm install -g pnpm
```

### 7.2 의존성 설치

```bash
cd web/dashboard

# 의존성 설치
pnpm install

# shadcn/ui 컴포넌트 추가 (필요시)
pnpm dlx shadcn-ui@latest add button
pnpm dlx shadcn-ui@latest add card
```

### 7.3 환경 변수 설정

```bash
# web/dashboard/.env.local
cat > web/dashboard/.env.local << 'EOF'
# API Endpoints
VITE_API_URL=http://localhost:8080
VITE_WS_URL=ws://localhost:8080

# AI Services
VITE_TRIAGE_API_URL=http://localhost:8001
VITE_COPILOT_API_URL=http://localhost:8002
VITE_AGENTIC_API_URL=http://localhost:8003

# Auth
VITE_KEYCLOAK_URL=http://localhost:8180
VITE_KEYCLOAK_REALM=siem
VITE_KEYCLOAK_CLIENT_ID=siem-dashboard
EOF
```

### 7.4 개발 서버 실행

```bash
cd web/dashboard

# 개발 서버 (HMR)
pnpm dev

# 다른 포트로 실행
pnpm dev --port 3001

# 네트워크 노출
pnpm dev --host
```

### 7.5 빌드

```bash
# 프로덕션 빌드
pnpm build

# 빌드 미리보기
pnpm preview

# 타입 체크
pnpm typecheck

# 린트
pnpm lint
```

---

## 8. Infrastructure 로컬 설정

### 8.1 Keycloak (인증 서버)

```bash
docker run -d \
  --name keycloak-dev \
  -p 8180:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:23.0 start-dev

# 관리 콘솔: http://localhost:8180
# admin / admin
```

#### Realm 설정

1. http://localhost:8180 접속
2. "Create realm" → "siem"
3. Clients → Create → "siem-dashboard"
4. Users → Create → 테스트 사용자 생성

### 8.2 Prometheus & Grafana (모니터링)

```bash
# Prometheus
docker run -d \
  --name prometheus-dev \
  -p 9090:9090 \
  -v $(pwd)/infra/monitoring/prometheus:/etc/prometheus \
  prom/prometheus:v2.48.0

# Grafana
docker run -d \
  --name grafana-dev \
  -p 3030:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=admin \
  grafana/grafana:10.2.0

# Grafana: http://localhost:3030 (admin/admin)
```

### 8.3 Vector (대안 파이프라인)

```bash
docker compose -f docker-compose.dev.yml --profile vector up -d vector
# Note: Requires --profile vector flag as it's an optional component
```

### 8.4 MinIO (S3 호환 스토리지)

```bash
docker run -d \
  --name minio-dev \
  -p 9000:9000 \
  -p 9001:9001 \
  -v minio_data:/data \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  quay.io/minio/minio server /data --console-address ":9001"

# Console: http://localhost:9001
```

---

## 9. 통합 개발 환경 (Docker Compose)

### 9.1 전체 스택 실행

프로젝트 루트에 `docker-compose.dev.yml` 생성:

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  # Databases
  clickhouse:
    image: clickhouse/clickhouse-server:24.1
    ports:
      - "8123:8123"
      - "9000:9000"
    environment:
      CLICKHOUSE_DB: siem
      CLICKHOUSE_USER: siem
      CLICKHOUSE_PASSWORD: siem_dev_password
    volumes:
      - clickhouse_data:/var/lib/clickhouse
      - ./infra/clickhouse/schemas:/docker-entrypoint-initdb.d

  postgres:
    image: postgres:15-alpine
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: siem
      POSTGRES_USER: siem
      POSTGRES_PASSWORD: siem_dev_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --requirepass siem_dev_password
    volumes:
      - redis_data:/data

  # Message Queue
  kafka:
    image: bitnami/kafka:3.6
    ports:
      - "9092:9092"
    environment:
      KAFKA_CFG_NODE_ID: 1
      KAFKA_CFG_PROCESS_ROLES: broker,controller
      KAFKA_CFG_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_CFG_LISTENERS: PLAINTEXT://:9092,CONTROLLER://:9093
      KAFKA_CFG_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_CFG_CONTROLLER_QUORUM_VOTERS: 1@kafka:9093
      ALLOW_PLAINTEXT_LISTENER: yes
    volumes:
      - kafka_data:/bitnami/kafka

  # Workflow
  temporal:
    image: temporalio/auto-setup:1.22
    ports:
      - "7233:7233"
    environment:
      DB: postgresql
      DB_PORT: 5432
      POSTGRES_USER: siem
      POSTGRES_PWD: siem_dev_password
      POSTGRES_SEEDS: postgres
    depends_on:
      - postgres

  temporal-ui:
    image: temporalio/ui:2.21
    ports:
      - "8088:8080"
    environment:
      TEMPORAL_ADDRESS: temporal:7233
    depends_on:
      - temporal

  # Auth
  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    ports:
      - "8180:8080"
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    command: start-dev

  # Monitoring
  prometheus:
    image: prom/prometheus:v2.48.0
    ports:
      - "9090:9090"
    volumes:
      - ./infra/monitoring/prometheus:/etc/prometheus

  grafana:
    image: grafana/grafana:10.2.0
    ports:
      - "3030:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin

volumes:
  clickhouse_data:
  postgres_data:
  redis_data:
  kafka_data:
```

### 9.2 실행 명령어

```bash
# 전체 인프라 시작
docker-compose -f docker-compose.dev.yml up -d

# 로그 확인
docker-compose -f docker-compose.dev.yml logs -f

# 특정 서비스만 시작
docker-compose -f docker-compose.dev.yml up -d clickhouse postgres redis kafka

# 중지
docker-compose -f docker-compose.dev.yml down

# 볼륨 포함 삭제
docker-compose -f docker-compose.dev.yml down -v
```

### 9.3 헬스 체크

```bash
# 모든 서비스 상태 확인
docker-compose -f docker-compose.dev.yml ps

# 개별 서비스 헬스 체크
curl http://localhost:8123/ping          # ClickHouse
docker exec postgres-dev pg_isready      # PostgreSQL
docker exec redis-dev redis-cli ping     # Redis
curl http://localhost:9092               # Kafka (connection test)
curl http://localhost:7233               # Temporal
```

---

## 10. 서비스 실행

### 10.1 전체 서비스 실행 순서

```bash
# 1. 인프라 시작
docker-compose -f docker-compose.dev.yml up -d

# 2. 마이그레이션 실행
migrate -path infra/postgres/migrations \
  -database "postgres://siem:siem_dev_password@localhost:5432/siem?sslmode=disable" up

# 3. Kafka 토픽 생성
./scripts/setup/create_topics.sh

# 4. Go 서비스 실행 (각각 다른 터미널)
cd services/gateway && go run main.go
cd services/detection && go run main.go
cd services/soar && go run main.go
cd services/query && go run main.go
cd services/collector && go run main.go

# 5. Python AI 서비스 실행
cd ai && poetry run uvicorn services.triage.main:app --port 8001
cd ai && poetry run uvicorn services.copilot.main:app --port 8002

# 6. Frontend 실행
cd web/dashboard && pnpm dev
```

### 10.2 Makefile 사용

```bash
# 전체 개발 환경 시작
make dev-up

# 개별 서비스 실행
make run-gateway
make run-detection
make run-ai-triage
make run-frontend

# 전체 중지
make dev-down
```

### 10.3 서비스 포트 목록

| 서비스 | 포트 | URL |
|--------|------|-----|
| API Gateway | 8080 | http://localhost:8080 |
| Detection Engine | 8081 | http://localhost:8081 |
| SOAR Engine | 8082 | http://localhost:8082 |
| TI Engine | 8083 | http://localhost:8083 |
| Query Service | 8084 | http://localhost:8084 |
| Case Service | 8085 | http://localhost:8085 |
| Collector | 8086 | http://localhost:8086 |
| Pipeline | 8087 | http://localhost:8087 |
| AI Triage | 8001 | http://localhost:8001 |
| AI Copilot | 8002 | http://localhost:8002 |
| AI Agentic | 8003 | http://localhost:8003 |
| Frontend | 3000 | http://localhost:3000 |
| ClickHouse HTTP | 8123 | http://localhost:8123 |
| PostgreSQL | 5432 | - |
| Redis | 6379 | - |
| Kafka | 9092 | - |
| Temporal | 7233 | - |
| Temporal UI | 8088 | http://localhost:8088 |
| Keycloak | 8180 | http://localhost:8180 |
| Prometheus | 9090 | http://localhost:9090 |
| Grafana | 3030 | http://localhost:3030 |

---

## 11. 테스트 실행

### 11.1 Go 유닛 테스트

```bash
# 전체 테스트
make go-test

# 개별 서비스 테스트
cd services/gateway && go test ./... -v

# 커버리지
cd services/gateway && go test ./... -cover -coverprofile=coverage.out
go tool cover -html=coverage.out

# 특정 테스트만 실행
go test ./... -run TestDetectionEngine -v
```

### 11.2 Python 유닛 테스트

```bash
cd ai

# 전체 테스트
poetry run pytest

# 상세 출력
poetry run pytest -v

# 커버리지
poetry run pytest --cov=. --cov-report=html

# 특정 테스트
poetry run pytest tests/test_triage.py -v

# 마커별 실행
poetry run pytest -m "not slow"
```

### 11.3 통합 테스트

```bash
# 인프라 실행 필요
docker-compose -f docker-compose.dev.yml up -d

# Go 통합 테스트
cd tests/integration/go && go test ./... -v -tags=integration

# Python 통합 테스트
cd tests/integration/python && poetry run pytest -v

# E2E 테스트
cd tests/integration/e2e && poetry run pytest -v
```

### 11.4 성능 테스트

```bash
# k6 설치
# macOS: brew install k6
# Windows: choco install k6

# 부하 테스트
k6 run tests/performance/k6/load_test.js

# 스트레스 테스트
k6 run tests/performance/k6/stress_test.js

# Locust (Python)
cd tests/performance/locust
poetry run locust -f locustfile.py --host=http://localhost:8080
# Web UI: http://localhost:8089
```

### 11.5 Frontend 테스트

```bash
cd web/dashboard

# 유닛 테스트
pnpm test

# 워치 모드
pnpm test:watch

# 커버리지
pnpm test:coverage

# E2E 테스트 (Playwright)
pnpm test:e2e
```

---

## 12. 트러블슈팅

### 12.1 Docker 관련

```bash
# 컨테이너 로그 확인
docker logs clickhouse-dev
docker logs postgres-dev

# 컨테이너 재시작
docker restart clickhouse-dev

# 볼륨 정리
docker volume prune

# 네트워크 문제
docker network ls
docker network inspect bridge
```

### 12.2 포트 충돌

```bash
# 사용 중인 포트 확인 (Linux/macOS)
lsof -i :8080
netstat -tulpn | grep 8080

# Windows
netstat -ano | findstr :8080

# 프로세스 종료
kill -9 <PID>
```

### 12.3 Go 빌드 오류

```bash
# 모듈 캐시 정리
go clean -modcache

# 의존성 재다운로드
go mod download

# vendor 사용
go mod vendor
go build -mod=vendor
```

### 12.4 Python 환경 문제

```bash
# Poetry 환경 재생성
poetry env remove python
poetry install

# pip 캐시 정리
pip cache purge

# PyTorch CUDA 버전 확인
python -c "import torch; print(torch.cuda.is_available())"
```

### 12.5 Kafka 연결 문제

```bash
# Kafka 상태 확인
docker exec kafka-dev kafka-broker-api-versions.sh \
  --bootstrap-server localhost:9092

# 토픽 목록
docker exec kafka-dev kafka-topics.sh --list \
  --bootstrap-server localhost:9092

# Consumer Group 상태
docker exec kafka-dev kafka-consumer-groups.sh \
  --bootstrap-server localhost:9092 \
  --describe --group siem-dev
```

### 12.6 ClickHouse 연결 문제

```bash
# HTTP 인터페이스 테스트
curl 'http://localhost:8123/?query=SELECT%201'

# 클라이언트 접속
docker exec -it clickhouse-dev clickhouse-client

# 쿼리 로그 확인
SELECT * FROM system.query_log ORDER BY event_time DESC LIMIT 10;
```

### 12.7 공통 환경 변수 문제

```bash
# 환경 변수 확인
env | grep SIEM
env | grep POSTGRES

# .env 파일 로드 테스트
source .env.local && echo $POSTGRES_HOST
```

---

## 빠른 시작 체크리스트

```bash
# 1. 사전 요구사항 확인
docker --version && go version && python --version && node --version

# 2. 인프라 시작
docker-compose -f docker-compose.dev.yml up -d

# 3. 헬스 체크
curl http://localhost:8123/ping  # ClickHouse
curl http://localhost:7233       # Temporal

# 4. DB 마이그레이션
migrate -path infra/postgres/migrations \
  -database "postgres://siem:siem_dev_password@localhost:5432/siem?sslmode=disable" up

# 5. 서비스 실행
cd services/gateway && go run main.go &
cd ai && poetry run uvicorn services.triage.main:app --port 8001 &
cd web/dashboard && pnpm dev &

# 6. 테스트
curl http://localhost:8080/health
open http://localhost:3000
```

---


## 13. 환경 설정 트러블슈팅 및 팁

### Go 명령어가 인식되지 않는 경우
Go 설치 후 터미널에서 `go` 명령어가 인식되지 않는다면 시스템 PATH에 Go 바이너리 경로가 누락되었을 수 있습니다.

1. **터미널 재시작**: 설치 직후에는 터미널을 재시작해야 PATH가 적용됩니다.
2. **수동 경로 추가**:
   - `C:\Program Files\Go\bin` 경로가 사용자 또는 시스템 PATH 환경 변수에 포함되어 있는지 확인하세요.
   - PowerShell에서 임시로 추가하려면: `$env:PATH = "$env:PATH;C:\Program Files\Go\bin"`

### Winget으로 설치한 Make가 인식되지 않는 경우
`winget install ezwinports.make`로 설치했으나 `make` 명령어가 작동하지 않는 경우, Winget 패키지 경로를 PATH에 추가해야 할 수 있습니다.

- **경로 확인**: `C:\Users\%USERNAME%\AppData\Local\Microsoft\WinGet\Packages\ezwinports.make_...\bin`
- 해당 경로를 사용자 환경 변수 `Path`에 추가하세요.

### Docker 버전 경고
현재 프로젝트는 Docker Desktop 24.0+를 권장하나, 이전 버전(20.x 등)에서도 기본적인 기능을 작동합니다. 단, 최신 `docker-compose` 기능 사용 시 문제가 생길 경우 업데이트를 권장합니다.

---

*마지막 업데이트: 2026-02-04*

