# SIEM-SOAR 통합 플랫폼

차세대 Security Information and Event Management (SIEM) + Security Orchestration, Automation and Response (SOAR) 통합 플랫폼

## 프로젝트 개요

| 항목 | 값 |
|------|-----|
| **버전** | v1.0.0 GA |
| **아키텍처** | MSA (마이크로서비스) |
| **배포 옵션** | SaaS / Hybrid / On-Premise |
| **목표 처리량** | 100K+ EPS |

---

## 기술 스택

| 레이어 | 기술 |
|--------|------|
| **Backend** | Go 1.21+ (Core Services), Python 3.11+ (AI), Rust (Agent) |
| **Frontend** | React 18, TypeScript 5, Vite, TailwindCSS, Zustand |
| **Database** | ClickHouse (OLAP), PostgreSQL 15+ (OLTP), Redis 7+ |
| **AI/ML** | PyTorch 2.x, LangChain, LangGraph, vLLM |
| **Streaming** | Apache Kafka (KRaft), Vector |
| **Infra** | Kubernetes, Terraform, ArgoCD, Helm |
| **Workflow** | Temporal |

---

## 디렉토리 구조

```
siem-soar-project/
├── services/              # Go 마이크로서비스 (8개)
│   ├── gateway/           # API Gateway (인증, 라우팅, Rate Limiting)
│   ├── detection/         # Detection Engine (Sigma, 상관분석)
│   ├── soar/              # SOAR Engine (Temporal 워크플로우)
│   ├── ti/                # Threat Intelligence (STIX/TAXII, MISP)
│   ├── query/             # Query Service (ClickHouse, Federation)
│   ├── case/              # Case Management
│   ├── collector/         # Log Collector (Syslog, HTTP, Kafka)
│   ├── pipeline/          # Data Pipeline
│   ├── parser/            # Parser Engine (Grok, CEF, LEEF)
│   ├── normalizer/        # UDM Normalizer
│   ├── enricher/          # Event Enricher (GeoIP, Asset, TI)
│   ├── router/            # Event Router
│   └── alert/             # Alert Service
│
├── pkg/                   # Go 공통 패키지
│   ├── config/            # 설정 관리
│   ├── logger/            # 구조화 로깅
│   ├── errors/            # 에러 타입
│   ├── middleware/        # HTTP 미들웨어
│   ├── repository/        # 데이터 접근 (ClickHouse, PostgreSQL, Redis)
│   └── connector/         # SIEM 커넥터 (Splunk, Elastic, Sentinel)
│
├── ai/                    # Python AI 서비스
│   ├── models/            # ML 모델
│   │   ├── classifier/    # Alert 분류 모델
│   │   ├── priority/      # 우선순위 모델
│   │   ├── nl2sql/        # NL2SQL 모델
│   │   ├── summarizer/    # 요약 모델
│   │   └── recommender/   # 추천 모델
│   ├── services/          # AI API 서비스
│   │   ├── triage/        # Alert Triage (FastAPI)
│   │   ├── copilot/       # LLM Copilot (FastAPI)
│   │   └── agentic/       # Agentic AI (FastAPI)
│   ├── agents/            # LangGraph 에이전트
│   │   ├── investigation/ # 조사 에이전트
│   │   ├── analysis/      # 분석 에이전트
│   │   ├── response/      # 대응 에이전트
│   │   ├── orchestrator/  # 오케스트레이터
│   │   ├── safety/        # 안전장치
│   │   └── healing/       # Self-Healing
│   ├── data/              # 데이터 파이프라인
│   ├── training/          # 학습 모듈
│   ├── feedback/          # 피드백 학습
│   ├── finetuning/        # 한국어 파인튜닝
│   ├── rag/               # RAG 파이프라인
│   └── integration/       # Kafka 통합
│
├── web/dashboard/         # React SOC 대시보드
│   └── src/
│       ├── components/    # UI 컴포넌트
│       │   ├── ui/        # shadcn/ui 기반
│       │   ├── layout/    # 레이아웃
│       │   └── widgets/   # 차트 위젯 (ECharts)
│       └── features/      # 기능별 모듈
│           ├── dashboard/ # SOC 대시보드
│           ├── alerts/    # Alert 관리
│           ├── cases/     # Case 관리
│           ├── query/     # 쿼리 콘솔
│           ├── playbooks/ # 플레이북 편집기
│           ├── copilot/   # AI Copilot 채팅
│           ├── agentic/   # Agentic 대시보드
│           └── auth/      # 인증
│
├── infra/                 # 인프라 코드
│   ├── terraform/         # IaC (GCP/AWS)
│   ├── helm/              # Kubernetes Helm Charts
│   ├── argocd/            # GitOps 설정
│   ├── monitoring/        # Prometheus, Grafana
│   ├── kafka/             # Kafka 클러스터
│   ├── clickhouse/        # ClickHouse 클러스터
│   ├── postgres/          # PostgreSQL 마이그레이션
│   ├── redis/             # Redis Sentinel
│   ├── temporal/          # Temporal Server
│   ├── llm/               # vLLM 서빙
│   ├── vector/            # Vector 파이프라인
│   └── secrets/           # 시크릿 관리
│
├── tests/                 # 테스트
│   ├── integration/       # 통합 테스트 (Go, Python, E2E)
│   ├── performance/       # 성능 테스트 (k6, Locust)
│   ├── security/          # 보안 테스트 (SAST, DAST)
│   ├── reliability/       # 가용성 테스트 (Chaos Mesh)
│   ├── fixtures/          # 테스트 데이터
│   └── mocks/             # 모킹 유틸
│
├── docs/                  # 문서
│   ├── adr/               # Architecture Decision Records
│   ├── api/               # API 문서 (OpenAPI)
│   ├── schema/            # 스키마 문서 (UDM)
│   ├── operations/        # 운영 가이드
│   └── user/              # 사용자 가이드
│
├── scripts/               # 스크립트
│   ├── deploy/            # 배포 스크립트
│   └── migration/         # 마이그레이션 스크립트
│
└── .github/workflows/     # CI/CD
```

---

## 핵심 서비스

### 1. Data Pipeline (100K+ EPS)
- **Collector**: Syslog, HTTP, Kafka, S3, API 폴링
- **Parser**: Grok, JSON, CEF, LEEF, Regex (자동 포맷 감지)
- **Normalizer**: Chronicle UDM 기반 정규화
- **Enricher**: GeoIP, Asset, User, Threat Intel
- **Router**: 조건부 라우팅, 다중 목적지

### 2. Detection Engine
- **Sigma 규칙**: sigma-go 통합, 로그 소스 매핑
- **상관분석**: 시간 윈도우, 집계, 시퀀스 탐지
- **TI 매칭**: Bloom Filter, Trie, Radix Tree (IP CIDR)

### 3. SOAR Engine
- **Temporal 워크플로우**: 플레이북 실행, 승인 게이트
- **50개 플레이북**: Enrichment, Containment, Notification, Remediation, Investigation, Compliance
- **액션 커넥터**: Email, Slack, Jira, Firewall, EDR, AD

### 4. AI Services
- **Alert Triage**: Transformer 기반 분류, 우선순위화 (정확도 85%+, FP 감소 40%)
- **LLM Copilot**: NL2SQL (80%+), 인시던트 요약, 한국어 SOLAR, RAG
- **Agentic AI**: 자동 조사/분석/대응 (30%+ 자동화)

### 5. Multi-SIEM Integration
- **Splunk**: HEC, REST API, SPL
- **Elastic**: Bulk Ingest, ES DSL, EQL
- **Sentinel**: Event Hub, KQL, Incident API
- **Query Federation**: 크로스 SIEM 쿼리

---

## 개발 명령어

### Go 서비스
```bash
# 빌드
make go-build

# 테스트
make go-test

# 린트
make go-lint

# 개별 서비스 실행
cd services/gateway && go run main.go
```

### Python AI
```bash
# 의존성 설치
cd ai && poetry install

# 테스트
poetry run pytest

# 서비스 실행
poetry run uvicorn services.triage.main:app --reload
poetry run uvicorn services.copilot.main:app --reload
poetry run uvicorn services.agentic.main:app --reload
```

### Frontend
```bash
# 의존성 설치
cd web/dashboard && pnpm install

# 개발 서버
pnpm dev

# 빌드
pnpm build

# 테스트
pnpm test
```

### 인프라
```bash
# Terraform 적용
cd infra/terraform/environments/dev
terraform init && terraform apply

# Helm 배포
helm upgrade --install siem-platform ./infra/helm/siem-platform

# ArgoCD 동기화
argocd app sync siem-platform
```

---

## 테스트

```bash
# 통합 테스트
cd tests/integration/go && go test ./...
cd tests/integration/python && pytest

# E2E 테스트
cd tests/integration/e2e && pytest

# 성능 테스트 (k6)
k6 run tests/performance/k6/load_test.js

# 보안 스캔
semgrep --config tests/security/sast/semgrep.yaml .
```

---

## 배포

### 환경
- **dev**: 개발 환경 (auto-sync)
- **staging**: 스테이징 환경 (auto-sync)
- **prod**: 프로덕션 환경 (manual sync)

### 배포 전략
```bash
# Rolling (기본)
./scripts/deploy/deploy.sh prod rolling

# Blue-Green
./scripts/deploy/blue_green.sh prod

# Canary
./scripts/deploy/canary.sh prod 10  # 10% 시작
```

### SLO
- **가용성**: 99.9%
- **지연 시간**: p99 < 1초
- **Alert 처리**: < 60초
- **데이터 신선도**: < 30초

---

## 주요 설정 파일

| 파일 | 용도 |
|------|------|
| `turbo.json` | Turborepo 파이프라인 |
| `ai/pyproject.toml` | Python 의존성 (Poetry) |
| `web/dashboard/package.json` | Frontend 의존성 |
| `infra/helm/*/values.yaml` | Helm 값 |
| `infra/terraform/environments/*/terraform.tfvars` | Terraform 변수 |

---

## 코드 스타일

### Go
- `gofmt`, `golint`, `staticcheck` 사용
- 구조화 로깅 (`slog`)
- 에러 래핑 (`fmt.Errorf`)

### Python
- `black`, `isort`, `ruff` 사용
- Type hints 필수
- Pydantic 모델 사용

### TypeScript
- ESLint + Prettier
- shadcn/ui 컴포넌트 사용
- Zustand 상태 관리

---

## 참고 문서

- [API 문서](./docs/api/openapi.yaml)
- [UDM 스키마](./docs/schema/udm.md)
- [배포 가이드](./docs/operations/deployment.md)
- [운영 런북](./docs/operations/runbook.md)
- [사용자 가이드](./docs/user/user_guide.md)
- [릴리스 노트](./RELEASE_NOTES.md)
- [변경 로그](./CHANGELOG.md)
