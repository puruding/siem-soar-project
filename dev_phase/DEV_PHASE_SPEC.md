# SIEM-SOAR 통합 플랫폼 개발 Phase 명세서

**생성일:** 2026-02-03
**기반 문서:** ./siem-soar-strategy
**분석 방식:** 동적 Phase 생성
**총 개발 기간:** 18개월

---

## 0. 참조 문서 인덱스

이 Phase 명세서는 `siem-soar-strategy` 디렉토리의 개발 항목 및 개발 문서와 연계됩니다.

### 0.1 개발 항목 참조 (09_개발항목)

| 항목 | 문서 경로 |
|------|----------|
| 개발항목 총괄 | [00.개발항목_총괄.md](../../siem-soar-strategy/09_개발항목/00.개발항목_총괄.md) |
| 성능 최적화 | [01.성능최적화.md](../../siem-soar-strategy/09_개발항목/01.성능최적화.md) |
| 자산관리 정책 | [02.자산관리_정책.md](../../siem-soar-strategy/09_개발항목/02.자산관리_정책.md) |
| ML 통합 | [03.ML통합.md](../../siem-soar-strategy/09_개발항목/03.ML통합.md) |
| 분석 보고 | [04.분석_보고.md](../../siem-soar-strategy/09_개발항목/04.분석_보고.md) |
| SOAR 자동 대응 | [05.SOAR_자동대응.md](../../siem-soar-strategy/09_개발항목/05.SOAR_자동대응.md) |
| 구성도 | [06.구성도.md](../../siem-soar-strategy/09_개발항목/06.구성도.md) |

### 0.2 개발 문서 참조 (10_개발문서)

#### Phase 1: 설계 문서

| 문서 | 경로 |
|------|------|
| 문서 목록 및 가이드 | [00.문서_목록_및_가이드.md](../../siem-soar-strategy/10_개발문서/00.문서_목록_및_가이드.md) |
| 모노레포 구조 설계서 | [Phase1/01.모노레포_구조_설계서.md](../../siem-soar-strategy/10_개발문서/Phase1/01.모노레포_구조_설계서.md) |
| Go 프로젝트 템플릿 명세 | [Phase1/02.Go_프로젝트_템플릿_명세.md](../../siem-soar-strategy/10_개발문서/Phase1/02.Go_프로젝트_템플릿_명세.md) |
| Python AI 서비스 명세 | [Phase1/03.Python_AI_서비스_명세.md](../../siem-soar-strategy/10_개발문서/Phase1/03.Python_AI_서비스_명세.md) |

#### Phase 2-3: 데이터 레이어

| 문서 | 경로 |
|------|------|
| ClickHouse 스키마 설계서 | [Phase2-3/01.ClickHouse_스키마_설계서.md](../../siem-soar-strategy/10_개발문서/Phase2-3/01.ClickHouse_스키마_설계서.md) |
| Kafka 토픽 설계서 | [Phase2-3/02.Kafka_토픽_설계서.md](../../siem-soar-strategy/10_개발문서/Phase2-3/02.Kafka_토픽_설계서.md) |
| PostgreSQL 스키마 설계서 | [Phase2-3/03.PostgreSQL_스키마_설계서.md](../../siem-soar-strategy/10_개발문서/Phase2-3/03.PostgreSQL_스키마_설계서.md) |

#### API 명세서

| 문서 | 경로 |
|------|------|
| Parser API 명세서 | [API/01.Parser_API_명세서.md](../../siem-soar-strategy/10_개발문서/API/01.Parser_API_명세서.md) |
| Asset API 명세서 | [API/02.Asset_API_명세서.md](../../siem-soar-strategy/10_개발문서/API/02.Asset_API_명세서.md) |
| Policy API 명세서 | [API/03.Policy_API_명세서.md](../../siem-soar-strategy/10_개발문서/API/03.Policy_API_명세서.md) |

#### ADR (Architecture Decision Records)

| 문서 | 경로 |
|------|------|
| ADR-001: 모노레포 vs 멀티레포 | [ADR/ADR-001_모노레포_vs_멀티레포.md](../../siem-soar-strategy/10_개발문서/ADR/ADR-001_모노레포_vs_멀티레포.md) |
| ADR-002: Go vs Rust 백엔드 | [ADR/ADR-002_Go_vs_Rust_백엔드.md](../../siem-soar-strategy/10_개발문서/ADR/ADR-002_Go_vs_Rust_백엔드.md) |
| ADR-003: ClickHouse 샤딩 전략 | [ADR/ADR-003_ClickHouse_샤딩_전략.md](../../siem-soar-strategy/10_개발문서/ADR/ADR-003_ClickHouse_샤딩_전략.md) |
| ADR-004: Kafka 파티셔닝 전략 | [ADR/ADR-004_Kafka_파티셔닝_전략.md](../../siem-soar-strategy/10_개발문서/ADR/ADR-004_Kafka_파티셔닝_전략.md) |

#### Interface 명세서

| 문서 | 경로 |
|------|------|
| UDM 명세서 | [Interface/01.UDM_명세서.md](../../siem-soar-strategy/10_개발문서/Interface/01.UDM_명세서.md) |
| Kafka 메시지 스키마 | [Interface/02.Kafka_메시지_스키마.md](../../siem-soar-strategy/10_개발문서/Interface/02.Kafka_메시지_스키마.md) |
| Parser 출력 인터페이스 | [Interface/03.Parser_출력_인터페이스.md](../../siem-soar-strategy/10_개발문서/Interface/03.Parser_출력_인터페이스.md) |

---

## 1. 프로젝트 분석 요약

### 1.1 기술 스택

| 레이어 | 기술 |
|--------|------|
| **Backend** | Go (Core), Python (AI), Rust (Agent) |
| **Frontend** | React, TypeScript, TailwindCSS, Zustand |
| **Database** | ClickHouse (OLAP), PostgreSQL (OLTP), Redis |
| **AI/ML** | PyTorch, LangChain, vLLM, SOLAR |
| **Streaming** | Apache Kafka, Vector |
| **Infra** | Kubernetes, Terraform, ArgoCD |
| **Workflow** | Temporal |

### 1.2 아키텍처 특성

| 항목 | 값 |
|------|-----|
| 아키텍처 스타일 | MSA (마이크로서비스) |
| 서비스 수 | 9개 핵심 서비스 |
| 외부 연동 | 6개 (Splunk, Elastic, Sentinel, MISP, KISA, EDR) |
| 배포 옵션 | SaaS / Hybrid / On-Premise |

### 1.3 핵심 결정 사항

- [x] **Frontend Phase**: 포함 (React SOC 대시보드)
- [x] **AI Phase**: 포함 (3단계: Basic → Advanced → Agentic)
- [x] **Integration Phase**: 포함 (Multi-SIEM 핵심 차별화)
- [ ] **Graph/Vector Phase**: 제외 (별도 DB 없음)
- [x] **총 Phase 수**: 13개

---

## 2. Phase 구조

### 2.1 Phase 개요

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         개발 Phase 구조 (18개월)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  전략 Phase 1: 기반 구축 (0-6개월)                                          │
│  ════════════════════════════════                                          │
│  ┌────────┐ ┌────────┐ ┌──────────┐ ┌─────────────┐ ┌────────────────┐    │
│  │ setup  │→│ infra  │→│   data   │→│  pipeline   │→│  backend-core  │    │
│  │ (2주)  │ │ (4주)  │ │  (4주)   │ │   (4주)     │ │    (6주)       │    │
│  └────────┘ └────────┘ └──────────┘ └─────────────┘ └────────────────┘    │
│                                                              ↓              │
│                          ┌────────────────┐  ┌────────────────┐            │
│                          │  integration   │→ │   ai-basic     │            │
│                          │    (4주)       │  │    (4주)       │            │
│                          └────────────────┘  └────────────────┘            │
│                                                      ↓                      │
│  ───────────────────────────────────────────────────────────────────────   │
│                                                                             │
│  전략 Phase 2: 지능화 (6-12개월)                                            │
│  ════════════════════════════════                                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────────┐                        │
│  │    soar    │→ │  frontend  │→ │  ai-advanced   │                        │
│  │   (4주)    │  │   (6주)    │  │  (LLM, 8주)    │                        │
│  └────────────┘  └────────────┘  └────────────────┘                        │
│                                           ↓                                 │
│  ───────────────────────────────────────────────────────────────────────   │
│                                                                             │
│  전략 Phase 3: 자율화 (12-18개월)                                           │
│  ════════════════════════════════                                          │
│  ┌────────────────┐  ┌────────────┐  ┌────────────┐                        │
│  │  ai-agentic    │→ │  test-qa   │→ │   deploy   │                        │
│  │    (8주)       │  │   (4주)    │  │   (2주)    │                        │
│  └────────────────┘  └────────────┘  └────────────┘                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Phase 목록

| 순서 | Phase ID | Phase명 | 기간 | 전략 Phase | 핵심 산출물 |
|------|----------|---------|------|-----------|------------|
| 1 | `setup` | Project Setup | 2주 | Phase 1 | 모노레포, 공통 설정 |
| 2 | `infra` | Infrastructure | 4주 | Phase 1 | K8s, CI/CD, IaC |
| 3 | `data` | Data Layer | 4주 | Phase 1 | ClickHouse, PostgreSQL |
| 4 | `pipeline` | Data Pipeline | 4주 | Phase 1 | 수집, 파싱, 정규화 |
| 5 | `backend-core` | Core Services | 6주 | Phase 1 | Detection, TI, Query |
| 6 | `integration` | Multi-SIEM | 4주 | Phase 1 | Splunk, Elastic 연동 |
| 7 | `ai-basic` | AI Alert Triage | 4주 | Phase 1 | ML 분류, FP 감소 |
| 8 | `soar` | SOAR Engine | 4주 | Phase 2 | 플레이북, 케이스 관리 |
| 9 | `frontend` | SOC Dashboard | 6주 | Phase 2 | React 대시보드 |
| 10 | `ai-advanced` | LLM Copilot | 8주 | Phase 2 | NL2SQL, 한국어 AI |
| 11 | `ai-agentic` | Agentic AI | 8주 | Phase 3 | 자동 조사/대응 |
| 12 | `test-qa` | Test & QA | 4주 | Phase 3 | 통합, 성능, 보안 |
| 13 | `deploy` | Deploy & GA | 2주 | Phase 3 | 프로덕션 배포 |

### 2.3 Phase 의존성

| Phase | 선행 의존성 | 병렬 가능 |
|-------|------------|----------|
| `setup` | - | - |
| `infra` | setup | - |
| `data` | setup | infra와 병렬 |
| `pipeline` | data | - |
| `backend-core` | pipeline | - |
| `integration` | pipeline | backend-core와 병렬 |
| `ai-basic` | backend-core, integration | - |
| `soar` | ai-basic | - |
| `frontend` | ai-basic | soar와 병렬 |
| `ai-advanced` | soar, frontend | - |
| `ai-agentic` | ai-advanced | - |
| `test-qa` | ai-agentic | - |
| `deploy` | test-qa | - |

---

## 3. Phase별 상세

### Phase 1: setup (프로젝트 초기화)

**목표:** 모노레포 구조 설정 및 공통 개발 환경 구축
**기간:** 2주 (Week 1-2)
**의존성:** 없음

#### 📚 참조 문서

- [모노레포 구조 설계서](../../siem-soar-strategy/10_개발문서/Phase1/01.모노레포_구조_설계서.md)
- [Go 프로젝트 템플릿 명세](../../siem-soar-strategy/10_개발문서/Phase1/02.Go_프로젝트_템플릿_명세.md)
- [Python AI 서비스 명세](../../siem-soar-strategy/10_개발문서/Phase1/03.Python_AI_서비스_명세.md)
- [ADR-001: 모노레포 vs 멀티레포](../../siem-soar-strategy/10_개발문서/ADR/ADR-001_모노레포_vs_멀티레포.md)

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| setup-T1 | 모노레포 초기화 | Turborepo/Nx 기반 모노레포 | `/` 루트 설정 |
| setup-T2 | Go 프로젝트 구조 | 공통 패키지, 서비스 템플릿 | `/services/`, `/pkg/` |
| setup-T3 | Python 프로젝트 구조 | Poetry, 공통 유틸 | `/ai/` |
| setup-T4 | 공통 설정 | ESLint, Prettier, pre-commit | `.config/` |
| setup-T5 | 문서 템플릿 | ADR, API 문서 템플릿 | `/docs/` |

#### 완료 조건
- [ ] 모노레포 구조 확정 및 빌드 성공
- [ ] Go/Python 서비스 템플릿 동작
- [ ] pre-commit 훅 설정

---

### Phase 2: infra (인프라)

**목표:** Kubernetes 클러스터 및 CI/CD 파이프라인 구축
**기간:** 4주 (Week 3-6)
**의존성:** setup

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| infra-T1 | K8s 클러스터 설계 | Node Pool, 네임스페이스 | 설계 문서 |
| infra-T2 | Terraform IaC | GCP/AWS 인프라 코드 | `/infra/terraform/` |
| infra-T3 | Helm Charts | 서비스별 Helm 차트 | `/infra/helm/` |
| infra-T4 | CI 파이프라인 | GitHub Actions 워크플로우 | `.github/workflows/` |
| infra-T5 | CD 파이프라인 | ArgoCD 설정 | `/infra/argocd/` |
| infra-T6 | 모니터링 스택 | Prometheus, Grafana | `/infra/monitoring/` |
| infra-T7 | 시크릿 관리 | Vault 또는 Sealed Secrets | `/infra/secrets/` |

#### 완료 조건
- [ ] K8s 클러스터 프로비저닝 완료
- [ ] CI/CD 파이프라인 동작 (빌드 → 테스트 → 배포)
- [ ] Grafana 대시보드 기본 설정

---

### Phase 3: data (데이터 레이어)

**목표:** ClickHouse 클러스터 및 PostgreSQL 스키마 구축
**기간:** 4주 (Week 3-6, infra와 병렬)
**의존성:** setup

#### 📚 참조 문서

- [ClickHouse 스키마 설계서](../../siem-soar-strategy/10_개발문서/Phase2-3/01.ClickHouse_스키마_설계서.md)
- [PostgreSQL 스키마 설계서](../../siem-soar-strategy/10_개발문서/Phase2-3/03.PostgreSQL_스키마_설계서.md)
- [UDM 명세서](../../siem-soar-strategy/10_개발문서/Interface/01.UDM_명세서.md)

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| data-T1 | ClickHouse 클러스터 | 3노드 Replicated 클러스터 | ClickHouse 운영 |
| data-T2 | UDM 스키마 설계 | Unified Data Model 정의 | 스키마 문서 |
| data-T3 | 이벤트 테이블 | 파티셔닝, TTL, 정렬키 | `events` 테이블 |
| data-T4 | PostgreSQL 스키마 | 메타데이터 모델 | migration 스크립트 |
| data-T5 | Redis 설정 | 클러스터, 캐시 정책 | Redis 운영 |
| data-T6 | Go Repository | ClickHouse/PG 접근 레이어 | `/pkg/repository/` |

#### 완료 조건
- [ ] ClickHouse 1TB/일 수집 테스트 통과
- [ ] PostgreSQL 마이그레이션 동작
- [ ] Repository 레이어 유닛 테스트 통과

---

### Phase 4: pipeline (Security Data Pipeline)

**목표:** 로그 수집, 파싱, 정규화, 보강 파이프라인 구축
**기간:** 4주 (Week 7-10)
**의존성:** data

#### 📚 참조 문서

- [Kafka 토픽 설계서](../../siem-soar-strategy/10_개발문서/Phase2-3/02.Kafka_토픽_설계서.md)
- [Parser API 명세서](../../siem-soar-strategy/10_개발문서/API/01.Parser_API_명세서.md)
- [Parser 출력 인터페이스](../../siem-soar-strategy/10_개발문서/Interface/03.Parser_출력_인터페이스.md)
- [Kafka 메시지 스키마](../../siem-soar-strategy/10_개발문서/Interface/02.Kafka_메시지_스키마.md)
- [ADR-004: Kafka 파티셔닝 전략](../../siem-soar-strategy/10_개발문서/ADR/ADR-004_Kafka_파티셔닝_전략.md)

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| pipeline-T1 | Kafka 클러스터 | 토픽 설계, 파티션 | Kafka 운영 |
| pipeline-T2 | 수집 컴포넌트 | Syslog, API Poller | `/services/collector/` |
| pipeline-T3 | Parser 엔진 | 자동 포맷 감지, Grok | `/services/parser/` |
| pipeline-T4 | Normalizer (UDM) | 필드 매핑, 타입 변환 | `/services/normalizer/` |
| pipeline-T5 | Enricher | GeoIP, 자산 매핑 | `/services/enricher/` |
| pipeline-T6 | Router | 조건부 라우팅 | `/services/router/` |
| pipeline-T7 | Vector 통합 | Vector 파이프라인 | `/infra/vector/` |

#### 완료 조건
- [ ] 100K EPS 처리량 달성
- [ ] 파싱 정확도 95%+
- [ ] E2E 파이프라인 테스트 통과

---

### Phase 5: backend-core (핵심 백엔드 서비스)

**목표:** 탐지 엔진, TI 엔진, 쿼리 서비스 구현
**기간:** 6주 (Week 11-16)
**의존성:** pipeline

#### 📚 참조 문서

- [Asset API 명세서](../../siem-soar-strategy/10_개발문서/API/02.Asset_API_명세서.md)
- [Policy API 명세서](../../siem-soar-strategy/10_개발문서/API/03.Policy_API_명세서.md)
- [자산관리 정책](../../siem-soar-strategy/09_개발항목/02.자산관리_정책.md)
- [성능최적화](../../siem-soar-strategy/09_개발항목/01.성능최적화.md)

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| core-T1 | Detection Engine 기본 | 규칙 실행 프레임워크 | `/services/detection/` |
| core-T2 | Sigma 규칙 엔진 | sigma-go 통합 | Sigma 실행기 |
| core-T3 | 상관분석 규칙 | 복합 조건 탐지 | 상관분석 모듈 |
| core-T4 | TI Engine | STIX/TAXII 클라이언트 | `/services/ti/` |
| core-T5 | IOC 매칭 | Bloom Filter 기반 | IOC 매칭 모듈 |
| core-T6 | Query Service | ClickHouse 쿼리 API | `/services/query/` |
| core-T7 | Alert 생성 | Alert 모델, 발행 | Alert 서비스 |
| core-T8 | API Gateway | 인증, 라우팅 | `/services/gateway/` |

#### 완료 조건
- [ ] Sigma 규칙 100개 실행 성공
- [ ] TI 피드 3개 이상 연동
- [ ] 쿼리 응답 시간 < 2초 (90%)

---

### Phase 6: integration (Multi-SIEM 통합)

**목표:** Splunk, Elastic, Sentinel 연동 구현
**기간:** 4주 (Week 11-14, backend-core와 병렬)
**의존성:** pipeline

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| intg-T1 | Connector 프레임워크 | 공통 인터페이스 | `/pkg/connector/` |
| intg-T2 | Splunk 커넥터 | HEC, REST API | Splunk 연동 |
| intg-T3 | Elastic 커넥터 | API, Beats 프로토콜 | Elastic 연동 |
| intg-T4 | Sentinel 커넥터 | Azure API, Event Hub | Sentinel 연동 |
| intg-T5 | 통합 쿼리 레이어 | 크로스 SIEM 쿼리 | Query Federation |
| intg-T6 | Sigma 배포 | 멀티플랫폼 룰 변환 | Sigma 배포기 |

#### 완료 조건
- [ ] Splunk 실시간 데이터 연동
- [ ] Elastic 실시간 데이터 연동
- [ ] 통합 쿼리 동작

---

### Phase 7: ai-basic (AI Alert Triage)

**목표:** ML 기반 Alert 분류 및 우선순위화
**기간:** 4주 (Week 17-20)
**의존성:** backend-core, integration

#### 📚 참조 문서

- [ML통합](../../siem-soar-strategy/09_개발항목/03.ML통합.md)
- [분석 보고](../../siem-soar-strategy/09_개발항목/04.분석_보고.md)

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| ai1-T1 | ML 모델 설계 | Alert 분류 모델 아키텍처 | 설계 문서 |
| ai1-T2 | 데이터 파이프라인 | 학습 데이터 수집 | ML 데이터 파이프라인 |
| ai1-T3 | 분류 모델 학습 | PyTorch 분류기 | `/ai/models/classifier/` |
| ai1-T4 | 우선순위 모델 | 위험도 스코어링 | 우선순위 모델 |
| ai1-T5 | 모델 서빙 | FastAPI + TorchServe | `/ai/services/triage/` |
| ai1-T6 | FP 학습 | 피드백 반영 파이프라인 | FP 학습 모듈 |
| ai1-T7 | Alert 통합 | Detection → AI → Alert | 통합 파이프라인 |

#### 완료 조건
- [ ] Alert 분류 정확도 85%+
- [ ] FP 감소 40%
- [ ] 모델 서빙 지연 < 100ms

---

### Phase 8: soar (SOAR 엔진)

**목표:** 플레이북 실행 및 케이스 관리 구현
**기간:** 4주 (Week 21-24)
**의존성:** ai-basic

#### 📚 참조 문서

- [SOAR 자동대응](../../siem-soar-strategy/09_개발항목/05.SOAR_자동대응.md)

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| soar-T1 | Temporal 설정 | 워크플로우 엔진 | Temporal 클러스터 |
| soar-T2 | 플레이북 모델 | 플레이북 스키마 | `/services/soar/` |
| soar-T3 | 플레이북 실행기 | Temporal Worker | 플레이북 실행기 |
| soar-T4 | 커넥터 프레임워크 | 액션 커넥터 | 커넥터 모듈 |
| soar-T5 | 케이스 관리 | 인시던트 CRUD | `/services/case/` |
| soar-T6 | 타임라인 | 이벤트 시계열 | 타임라인 모듈 |
| soar-T7 | 승인 워크플로우 | Human-in-the-loop | 승인 모듈 |
| soar-T8 | 플레이북 라이브러리 | 사전 정의 50개 | 플레이북 템플릿 |

#### 완료 조건
- [ ] 플레이북 50개 동작
- [ ] 케이스 CRUD 완료
- [ ] 승인 워크플로우 동작

---

### Phase 9: frontend (SOC 대시보드)

**목표:** React 기반 SOC 대시보드 및 케이스 관리 UI
**기간:** 6주 (Week 21-26, soar와 병렬)
**의존성:** ai-basic

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| fe-T1 | 프로젝트 설정 | React, TypeScript, Vite | `/web/` |
| fe-T2 | 디자인 시스템 | TailwindCSS, 컴포넌트 | 디자인 시스템 |
| fe-T3 | 인증/인가 | Keycloak 연동 | Auth 모듈 |
| fe-T4 | SOC 대시보드 | 실시간 현황 | 대시보드 화면 |
| fe-T5 | Alert 목록 | 필터, 정렬, 검색 | Alert 화면 |
| fe-T6 | 케이스 관리 UI | 케이스 상세, 타임라인 | 케이스 화면 |
| fe-T7 | 쿼리 콘솔 | SQL 에디터, 결과 | 쿼리 화면 |
| fe-T8 | 플레이북 편집기 | 시각적 편집기 | 플레이북 화면 |
| fe-T9 | 위젯 라이브러리 | ECharts 차트 | 위젯 모듈 |

#### 완료 조건
- [ ] 주요 화면 5개 완료
- [ ] 반응형 디자인
- [ ] E2E 테스트 통과

---

### Phase 10: ai-advanced (LLM Copilot)

**목표:** 자연어 쿼리, 인시던트 요약, 한국어 AI
**기간:** 8주 (Week 27-34)
**의존성:** soar, frontend

#### 📚 참조 문서

- [ML통합](../../siem-soar-strategy/09_개발항목/03.ML통합.md)
- [분석 보고](../../siem-soar-strategy/09_개발항목/04.분석_보고.md)

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| ai2-T1 | LLM 인프라 | vLLM 서빙, GPU 노드 | LLM 서버 |
| ai2-T2 | NL2SQL 모델 | 자연어 → SQL 변환 | `/ai/models/nl2sql/` |
| ai2-T3 | 인시던트 요약 | 자동 상황 요약 | 요약 모듈 |
| ai2-T4 | 대응 권장 | 플레이북 추천 | 추천 모듈 |
| ai2-T5 | 한국어 파인튜닝 | SOLAR 파인튜닝 | 한국어 모델 |
| ai2-T6 | RAG 파이프라인 | 문서 검색 보강 | RAG 모듈 |
| ai2-T7 | Copilot API | LangChain 통합 | `/ai/services/copilot/` |
| ai2-T8 | Copilot UI | 채팅 인터페이스 | 프론트엔드 통합 |

#### 완료 조건
- [ ] NL2SQL 정확도 80%+
- [ ] 한국어 응답 품질
- [ ] 사용자 만족도 조사

---

### Phase 11: ai-agentic (Agentic AI)

**목표:** 자동 조사 및 자율 대응 AI 에이전트
**기간:** 8주 (Week 35-42)
**의존성:** ai-advanced

#### 📚 참조 문서

- [ML통합](../../siem-soar-strategy/09_개발항목/03.ML통합.md)
- [SOAR 자동대응](../../siem-soar-strategy/09_개발항목/05.SOAR_자동대응.md)

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| ai3-T1 | Agent 아키텍처 | LangGraph 기반 설계 | 설계 문서 |
| ai3-T2 | 조사 에이전트 | 컨텍스트 자동 수집 | Investigation Agent |
| ai3-T3 | 분석 에이전트 | 원인 분석 AI | Analysis Agent |
| ai3-T4 | 대응 에이전트 | 자동 실행 제안 | Response Agent |
| ai3-T5 | 오케스트레이터 | 에이전트 조율 | Orchestrator |
| ai3-T6 | 안전장치 | 승인, 롤백 | Safety Module |
| ai3-T7 | Self-Healing | 플레이북 최적화 | Self-Healing 모듈 |
| ai3-T8 | 자율 SOC 대시보드 | 에이전트 모니터링 | Agentic 대시보드 |

#### 완료 조건
- [ ] 자동 조사 비율 30%+
- [ ] 자동 대응 비율 30%+
- [ ] 안전장치 동작 검증

---

### Phase 12: test-qa (테스트 및 QA)

**목표:** 통합 테스트, 성능 테스트, 보안 감사
**기간:** 4주 (Week 43-46)
**의존성:** ai-agentic

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| qa-T1 | 통합 테스트 | E2E 시나리오 | 통합 테스트 스위트 |
| qa-T2 | 성능 테스트 | 부하, 스트레스 | 성능 리포트 |
| qa-T3 | 보안 테스트 | 침투 테스트, SAST | 보안 리포트 |
| qa-T4 | 가용성 테스트 | 장애 복구, DR | HA 테스트 |
| qa-T5 | 문서화 | API 문서, 운영 가이드 | 문서 완성 |
| qa-T6 | 버그 수정 | 이슈 해결 | 버그 수정 |

#### 완료 조건
- [ ] 테스트 커버리지 80%+
- [ ] 성능 목표 달성
- [ ] 보안 감사 통과

---

### Phase 13: deploy (배포 및 GA)

**목표:** 프로덕션 배포 및 v1.0 GA 릴리스
**기간:** 2주 (Week 47-48)
**의존성:** test-qa

#### Tasks

| Task ID | Task명 | 설명 | 산출물 |
|---------|--------|------|--------|
| deploy-T1 | 프로덕션 환경 | 인프라 프로비저닝 | Production 환경 |
| deploy-T2 | 데이터 마이그레이션 | 스키마 적용 | 마이그레이션 |
| deploy-T3 | 배포 자동화 | Blue-Green 배포 | 배포 파이프라인 |
| deploy-T4 | 모니터링 설정 | 알림, 대시보드 | 운영 모니터링 |
| deploy-T5 | GA 릴리스 | 버전 태깅, 릴리스 노트 | v1.0 GA |

#### 완료 조건
- [ ] 프로덕션 배포 완료
- [ ] 모니터링 알림 동작
- [ ] GA 릴리스 완료

---

## 4. 기능-Phase 매핑 표

| 기능 ID | 기능명 | 우선순위 | 관련 Phase |
|---------|--------|---------|-----------|
| F1.1 | Security Data Pipeline | P0 | pipeline |
| F1.2 | ClickHouse 저장소 | P0 | data |
| F2.1 | 규칙 기반 탐지 | P0 | backend-core |
| F2.2 | ML 기반 탐지 | P1-P2 | ai-basic, ai-advanced |
| F3.1 | AI Alert Triage | P0 | ai-basic |
| F3.2 | LLM Copilot | P1 | ai-advanced |
| F3.3 | Agentic AI | P2-P3 | ai-agentic |
| F4.1 | 플레이북 관리 | P0 | soar |
| F4.2 | 자동화 실행 | P0-P1 | soar |
| F4.3 | 케이스 관리 | P0 | soar, frontend |
| F5 | 위협 인텔리전스 | P0-P1 | backend-core |
| F6 | Multi-SIEM 통합 | P0-P1 | integration |
| F7.1 | 대시보드 | P0 | frontend |
| F7.2 | 리포팅 | P1-P2 | frontend, ai-advanced |

---

## 5. 전체 일정

| Phase | 시작 | 종료 | 기간 | 전략 Phase |
|-------|------|------|------|-----------|
| setup | W1 | W2 | 2주 | Phase 1 |
| infra | W3 | W6 | 4주 | Phase 1 |
| data | W3 | W6 | 4주 | Phase 1 |
| pipeline | W7 | W10 | 4주 | Phase 1 |
| backend-core | W11 | W16 | 6주 | Phase 1 |
| integration | W11 | W14 | 4주 | Phase 1 |
| ai-basic | W17 | W20 | 4주 | Phase 1 |
| soar | W21 | W24 | 4주 | Phase 2 |
| frontend | W21 | W26 | 6주 | Phase 2 |
| ai-advanced | W27 | W34 | 8주 | Phase 2 |
| ai-agentic | W35 | W42 | 8주 | Phase 3 |
| test-qa | W43 | W46 | 4주 | Phase 3 |
| deploy | W47 | W48 | 2주 | Phase 3 |

**마일스톤:**
- **M6 (W24):** Alpha 릴리스, PoC 3개사
- **M12 (W48):** v1.0 GA, 계약 10개사
- **M18 (W72):** v2.0 GA, 계약 20개사

---

## 6. 실행 명령어

각 Phase는 `/dev-executor` 스킬로 실행합니다.

```bash
# Phase 1: setup
claude "/dev-executor --phase=setup --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 2: infra (setup 완료 후)
claude "/dev-executor --phase=infra --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 3: data (setup 완료 후, infra와 병렬 가능)
claude "/dev-executor --phase=data --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 4: pipeline (data 완료 후)
claude "/dev-executor --phase=pipeline --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 5: backend-core (pipeline 완료 후)
claude "/dev-executor --phase=backend-core --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 6: integration (pipeline 완료 후, backend-core와 병렬)
claude "/dev-executor --phase=integration --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 7: ai-basic (backend-core, integration 완료 후)
claude "/dev-executor --phase=ai-basic --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 8: soar (ai-basic 완료 후)
claude "/dev-executor --phase=soar --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 9: frontend (ai-basic 완료 후, soar와 병렬)
claude "/dev-executor --phase=frontend --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 10: ai-advanced (soar, frontend 완료 후)
claude "/dev-executor --phase=ai-advanced --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 11: ai-agentic (ai-advanced 완료 후)
claude "/dev-executor --phase=ai-agentic --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 12: test-qa (ai-agentic 완료 후)
claude "/dev-executor --phase=test-qa --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"

# Phase 13: deploy (test-qa 완료 후)
claude "/dev-executor --phase=deploy --spec_file='./siem-soar-strategy/DEV_PHASE_SPEC.md'"
```

---

## 7. 산출물 디렉토리 구조

```
siem-soar-platform/
├── .github/
│   └── workflows/          # CI/CD
├── docs/
│   ├── adr/               # Architecture Decision Records
│   └── api/               # API 문서
├── infra/
│   ├── terraform/         # IaC
│   ├── helm/              # Kubernetes 차트
│   ├── argocd/            # GitOps
│   └── vector/            # Vector 설정
├── services/              # Go 서비스
│   ├── gateway/           # API Gateway
│   ├── detection/         # Detection Engine
│   ├── soar/              # SOAR Engine
│   ├── ti/                # TI Engine
│   ├── query/             # Query Service
│   ├── case/              # Case Manager
│   ├── collector/         # Data Collector
│   └── pipeline/          # Data Pipeline
├── ai/                    # Python AI 서비스
│   ├── models/            # ML 모델
│   └── services/          # AI 서비스
│       ├── triage/        # Alert Triage
│       ├── copilot/       # LLM Copilot
│       └── agentic/       # Agentic AI
├── web/                   # React Frontend
│   └── src/
├── pkg/                   # Go 공통 패키지
│   ├── repository/
│   └── connector/
└── scripts/               # 유틸리티 스크립트
```

---

*문서 생성일: 2026-02-03*
*버전: 1.0*
