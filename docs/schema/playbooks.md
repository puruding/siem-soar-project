# Playbooks 스키마 문서

> **문서 버전**: v1.0
> **최종 수정**: 2026-02-19
> **관련 마이그레이션**: `000008_playbooks_simplified.up.sql`

---

## 1. 개요

SOAR 플레이북 저장을 위한 PostgreSQL 스키마입니다. React Dashboard의 ReactFlow 기반 플레이북 에디터와 직접 연동됩니다.

### 1.1 설계 원칙

1. **프론트엔드 호환성**: ReactFlow 그래프 구조(nodes, edges) 직접 저장
2. **유연한 ID 형식**: `PB-{timestamp}` 형식의 TEXT ID 지원
3. **JSONB 활용**: 동적 구조의 플레이북 정의 저장
4. **MVP 우선**: 필수 기능만 포함한 간소화된 스키마

---

## 2. 테이블 구조

### 2.1 soar.playbooks

```sql
CREATE TABLE soar.playbooks (
    id TEXT PRIMARY KEY,                    -- "PB-1771431484622" 형식
    tenant_id TEXT NOT NULL,                -- 멀티테넌트 지원
    name VARCHAR(255) NOT NULL,             -- 내부 이름
    display_name VARCHAR(255),              -- 표시 이름
    description TEXT,                       -- 설명
    category VARCHAR(100) DEFAULT 'custom', -- 카테고리
    version INTEGER DEFAULT 1,              -- 버전
    is_latest BOOLEAN DEFAULT TRUE,         -- 최신 버전 여부
    definition JSONB NOT NULL,              -- 플레이북 정의 (nodes, edges, variables)
    trigger_config JSONB,                   -- 트리거 설정
    trigger_type VARCHAR(50),               -- manual, alert, schedule, webhook
    status VARCHAR(20) DEFAULT 'DRAFT',     -- DRAFT, TESTING, ACTIVE, DISABLED
    is_enabled BOOLEAN DEFAULT FALSE,       -- 활성화 여부
    tags TEXT[],                            -- 태그 배열
    created_at TIMESTAMPTZ,                 -- 생성 시각
    updated_at TIMESTAMPTZ                  -- 수정 시각
);
```

### 2.2 컬럼 상세 설명

| 컬럼 | 타입 | 필수 | 기본값 | 설명 |
|------|------|------|--------|------|
| `id` | TEXT | O | - | 플레이북 고유 ID (`PB-{timestamp}` 형식) |
| `tenant_id` | TEXT | O | 기본 테넌트 UUID | 멀티테넌트 격리용 |
| `name` | VARCHAR(255) | O | - | 플레이북 내부 이름 |
| `display_name` | VARCHAR(255) | X | - | UI 표시용 이름 |
| `description` | TEXT | X | - | 플레이북 설명 |
| `category` | VARCHAR(100) | X | 'custom' | 카테고리 (custom, containment, investigation 등) |
| `version` | INTEGER | X | 1 | 버전 번호 |
| `is_latest` | BOOLEAN | X | TRUE | 최신 버전 플래그 |
| `definition` | JSONB | O | '{}' | 플레이북 정의 (아래 상세 구조 참조) |
| `trigger_config` | JSONB | X | '{}' | 트리거 조건 설정 |
| `trigger_type` | VARCHAR(50) | X | 'manual' | 트리거 유형 |
| `status` | VARCHAR(20) | X | 'DRAFT' | 플레이북 상태 |
| `is_enabled` | BOOLEAN | X | FALSE | 활성화 여부 |
| `tags` | TEXT[] | X | '{}' | 검색/필터용 태그 |
| `created_at` | TIMESTAMPTZ | X | CURRENT_TIMESTAMP | 생성 시각 |
| `updated_at` | TIMESTAMPTZ | X | CURRENT_TIMESTAMP | 수정 시각 (자동 갱신) |

---

## 3. Definition JSONB 구조

### 3.1 전체 구조

```json
{
  "nodes": [...],      // ReactFlow 노드 배열
  "edges": [...],      // ReactFlow 엣지 배열
  "variables": [...]   // 플레이북 변수 배열
}
```

### 3.2 Node 구조

```json
{
  "id": "trigger-1",
  "type": "trigger",           // trigger, action, decision, integration, loop, parallel, wait, approval
  "position": {
    "x": 250,
    "y": 50
  },
  "data": {
    "label": "Alert Trigger",
    "triggerType": "alert",    // 노드 타입별 추가 속성
    "description": "..."
  }
}
```

**노드 타입별 data 속성**

| 노드 타입 | data 속성 |
|----------|----------|
| `trigger` | `triggerType`, `conditions` |
| `action` | `actionType`, `parameters` |
| `decision` | `condition`, `onTrue`, `onFalse` |
| `integration` | `integrationType`, `connector`, `action`, `parameters` |
| `approval` | `approverRoles`, `timeout`, `escalation` |
| `loop` | `iterateOver`, `maxIterations` |
| `parallel` | `branches` |
| `wait` | `duration`, `condition` |

### 3.3 Edge 구조

```json
{
  "id": "e1",
  "source": "trigger-1",       // 시작 노드 ID
  "target": "action-1",        // 종료 노드 ID
  "type": "labeled",           // 엣지 타입
  "label": "on_success",       // 조건 레이블 (선택)
  "data": {}
}
```

### 3.4 Variable 구조

```json
{
  "id": "var-1",
  "name": "alert_severity",
  "type": "string",            // string, number, boolean, array, object
  "scope": "global",           // global, node, execution
  "value": "high",
  "description": "Alert 심각도",
  "nodeId": null               // scope가 'node'인 경우 해당 노드 ID
}
```

**변수 범위 (Scope)**

| 범위 | 설명 | 사용 예 |
|------|------|--------|
| `global` | 플레이북 전체에서 사용 | 설정값, 임계값 |
| `node` | 특정 노드에서만 사용 | 노드별 파라미터 |
| `execution` | 실행 시 입력받는 변수 | Alert 정보, 사용자 입력 |

---

## 4. 상태 값

### 4.1 trigger_type

| 값 | 설명 |
|----|------|
| `manual` | 수동 실행 |
| `alert` | Alert 발생 시 자동 트리거 |
| `schedule` | 스케줄 기반 실행 |
| `webhook` | 외부 웹훅 호출 시 실행 |

### 4.2 status

| 값 | 설명 | UI 표시 |
|----|------|--------|
| `DRAFT` | 작성 중 | 🟡 Draft |
| `TESTING` | 테스트 중 | 🔵 Testing |
| `ACTIVE` | 운영 중 | 🟢 Active |
| `DISABLED` | 비활성화 | ⚫ Disabled |

---

## 5. 인덱스

```sql
-- 테넌트별 조회
CREATE INDEX idx_playbooks_simplified_tenant ON soar.playbooks(tenant_id);

-- 상태별 필터링
CREATE INDEX idx_playbooks_simplified_status ON soar.playbooks(status);

-- 카테고리별 필터링
CREATE INDEX idx_playbooks_simplified_category ON soar.playbooks(category);

-- 활성화된 플레이북만 조회
CREATE INDEX idx_playbooks_simplified_enabled ON soar.playbooks(is_enabled) WHERE is_enabled = TRUE;

-- 트리거 타입별 조회
CREATE INDEX idx_playbooks_simplified_trigger_type ON soar.playbooks(trigger_type);

-- 태그 검색 (GIN 인덱스)
CREATE INDEX idx_playbooks_simplified_tags ON soar.playbooks USING GIN (tags);

-- 최신순 정렬
CREATE INDEX idx_playbooks_simplified_created ON soar.playbooks(created_at DESC);
```

---

## 6. API 매핑

### 6.1 REST API 엔드포인트

| Method | Endpoint | 설명 |
|--------|----------|------|
| GET | `/api/v1/playbooks` | 플레이북 목록 조회 |
| POST | `/api/v1/playbooks` | 플레이북 생성 |
| GET | `/api/v1/playbooks/{id}` | 플레이북 상세 조회 |
| PUT | `/api/v1/playbooks/{id}` | 플레이북 수정 |
| DELETE | `/api/v1/playbooks/{id}` | 플레이북 삭제 |

### 6.2 요청/응답 예시

**POST /api/v1/playbooks**

```json
{
  "id": "PB-1771431484622",
  "name": "Brute Force Response",
  "display_name": "Brute Force 대응",
  "description": "SSH Brute Force 공격 대응 플레이북",
  "category": "containment",
  "trigger_type": "alert",
  "enabled": false,
  "tags": ["ssh", "brute-force", "containment"],
  "nodes": [
    {
      "id": "trigger-1",
      "type": "trigger",
      "position": {"x": 250, "y": 50},
      "data": {"label": "Alert Trigger", "triggerType": "alert"}
    },
    {
      "id": "action-1",
      "type": "action",
      "position": {"x": 250, "y": 150},
      "data": {"label": "Block IP", "actionType": "firewall_block"}
    }
  ],
  "edges": [
    {"id": "e1", "source": "trigger-1", "target": "action-1", "type": "labeled"}
  ],
  "variables": [
    {"id": "var-1", "name": "block_duration", "type": "number", "scope": "global", "value": 3600}
  ]
}
```

**응답**

```json
{
  "id": "PB-1771431484622",
  "message": "Playbook created successfully",
  "version": 1
}
```

---

## 7. 기존 스키마와의 차이점

| 항목 | 000006_playbooks (Full) | 000008_playbooks_simplified |
|------|------------------------|----------------------------|
| ID 타입 | UUID | TEXT (`PB-{timestamp}`) |
| 외래키 | tenants, users 참조 | 없음 (TEXT tenant_id) |
| 실행 통계 | execution_count, success_count 등 | 없음 |
| MITRE 매핑 | mitre_tactics, mitre_techniques | 없음 |
| 승인 설정 | approval_config JSONB | 없음 (노드에서 처리) |
| 타임아웃 | timeout_minutes, max_retries 등 | 없음 |
| 복잡도 | 30+ 컬럼 | 15 컬럼 |

---

## 8. 마이그레이션 가이드

### 8.1 신규 설치

```bash
# 마이그레이션 실행
migrate -path infra/postgres/migrations \
  -database "postgres://siem:siem_password@localhost:5432/siem_soar?sslmode=disable" \
  up
```

### 8.2 기존 데이터 마이그레이션

기존 `000006_playbooks` 테이블에서 데이터 마이그레이션이 필요한 경우:

```sql
-- 기존 테이블 백업
CREATE TABLE soar.playbooks_backup AS SELECT * FROM soar.playbooks;

-- 기존 테이블 삭제
DROP TABLE soar.playbooks CASCADE;

-- 새 스키마 적용 (000008 마이그레이션 실행)
-- 이후 데이터 마이그레이션 스크립트 실행
```

---

## 9. 관련 문서

- [DEVELOPMENT_SETUP.md](../../docs/DEVELOPMENT_SETUP.md) - 개발 환경 설정
- [04_Response_테스트케이스.md](../../../siem-soar-strategy/12_테스트케이스/04_Response_테스트케이스.md) - Response 계층 테스트
- [UDM 스키마](./udm.md) - Unified Data Model 스키마

---

*마지막 업데이트: 2026-02-19*
