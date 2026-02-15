# Unified Data Model (UDM) 스키마 문서

## 개요

SIEM-SOAR 플랫폼의 Unified Data Model(UDM)은 Google Chronicle의 UDM을 기반으로 설계되었습니다.
다양한 보안 데이터 소스의 이벤트를 일관된 형식으로 정규화하여 탐지, 분석, 대응 워크플로우를 지원합니다.

## 설계 원칙

1. **벤더 중립성**: 특정 벤더 종속성 없이 모든 보안 이벤트 표현
2. **확장성**: 새로운 필드와 이벤트 유형 쉽게 추가
3. **성능 최적화**: ClickHouse 컬럼 스토리지에 최적화된 구조
4. **상호 운용성**: STIX, MITRE ATT&CK 등 표준과 호환

## 이벤트 카테고리

| 카테고리 | 코드 | 설명 |
|---------|------|------|
| GENERIC_EVENT | 0 | 분류되지 않은 일반 이벤트 |
| NETWORK_CONNECTION | 100 | 네트워크 연결 이벤트 |
| NETWORK_DNS | 101 | DNS 쿼리/응답 |
| NETWORK_DHCP | 102 | DHCP 이벤트 |
| NETWORK_HTTP | 103 | HTTP 요청/응답 |
| NETWORK_FLOW | 104 | 네트워크 플로우 |
| NETWORK_EMAIL | 110 | 이메일 이벤트 |
| USER_LOGIN | 200 | 사용자 로그인 |
| USER_LOGOUT | 201 | 사용자 로그아웃 |
| USER_CREATION | 202 | 사용자 생성 |
| USER_CHANGE | 203 | 사용자 변경 |
| USER_DELETION | 204 | 사용자 삭제 |
| USER_PRIVILEGE_CHANGE | 205 | 권한 변경 |
| PROCESS_LAUNCH | 300 | 프로세스 시작 |
| PROCESS_TERMINATION | 301 | 프로세스 종료 |
| PROCESS_INJECTION | 302 | 프로세스 인젝션 |
| FILE_CREATION | 400 | 파일 생성 |
| FILE_MODIFICATION | 401 | 파일 수정 |
| FILE_DELETION | 402 | 파일 삭제 |
| FILE_READ | 403 | 파일 읽기 |
| REGISTRY_CREATION | 500 | 레지스트리 키 생성 |
| REGISTRY_MODIFICATION | 501 | 레지스트리 수정 |
| REGISTRY_DELETION | 502 | 레지스트리 삭제 |
| RESOURCE_ACCESS | 600 | 리소스 접근 |
| RESOURCE_PERMISSION_CHANGE | 601 | 권한 변경 |
| SERVICE_START | 700 | 서비스 시작 |
| SERVICE_STOP | 701 | 서비스 중지 |
| SCHEDULED_TASK | 702 | 스케줄 태스크 |
| ALERT | 800 | 보안 알림 |
| SCAN_NETWORK | 900 | 네트워크 스캔 |
| SCAN_VULNERABILITY | 901 | 취약점 스캔 |

## 핵심 엔티티

### 1. Principal (주체)

이벤트의 주체를 나타냅니다 (사용자, 시스템, 프로세스).

```
principal {
    hostname: string           # 호스트명
    ip: Array(IPv6)           # IP 주소 목록
    mac: Array(string)        # MAC 주소 목록
    port: UInt16              # 포트
    asset_id: string          # 자산 ID
    user {
        userid: string        # 사용자 ID
        user_display_name: string  # 표시명
        email_addresses: Array(string)
        group_identifiers: Array(string)
        windows_sid: string
    }
    process {
        pid: UInt64           # 프로세스 ID
        file {
            full_path: string
            sha256: string
            md5: string
            sha1: string
        }
        command_line: string
        parent_process {
            pid: UInt64
            file { ... }
        }
    }
    administrative_domain: string  # 도메인
    platform: Enum8           # WINDOWS, LINUX, MAC, etc.
    platform_version: string
}
```

### 2. Target (대상)

이벤트의 대상을 나타냅니다.

```
target {
    hostname: string
    ip: Array(IPv6)
    mac: Array(string)
    port: UInt16
    asset_id: string
    url: string
    user { ... }              # principal.user와 동일
    process { ... }           # principal.process와 동일
    file { ... }
    registry {
        registry_key: string
        registry_value_name: string
        registry_value_data: string
    }
    resource {
        name: string
        type: string
        id: string
    }
    application: string
}
```

### 3. Network (네트워크)

네트워크 관련 정보입니다.

```
network {
    application_protocol: Enum8  # HTTP, DNS, SSH, etc.
    direction: Enum8          # INBOUND, OUTBOUND
    ip_protocol: Enum8        # TCP, UDP, ICMP
    received_bytes: UInt64
    sent_bytes: UInt64
    received_packets: UInt64
    sent_packets: UInt64
    session_duration: Float64
    session_id: string
    dns {
        questions: Array(Tuple(name String, type UInt16))
        answers: Array(Tuple(name String, type UInt16, data String, ttl UInt32))
        response_code: UInt8
    }
    http {
        method: string
        referral_url: string
        response_code: UInt16
        user_agent: string
    }
    email {
        from: string
        to: Array(string)
        cc: Array(string)
        subject: string
        attachment_names: Array(string)
    }
    tls {
        cipher: string
        version: string
        ja3: string
        ja3s: string
        certificate {
            serial: string
            issuer: string
            subject: string
            not_before: DateTime64(3)
            not_after: DateTime64(3)
        }
    }
}
```

### 4. Security Result (보안 결과)

탐지 결과 및 위협 정보입니다.

```
security_result {
    action: Enum8             # ALLOW, BLOCK, QUARANTINE, etc.
    severity: Enum8           # UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL
    confidence: Float32       # 0.0 - 1.0
    category: string          # 탐지 카테고리
    category_details: Array(string)
    rule_id: string
    rule_name: string
    rule_type: Enum8          # SIGMA, YARA, CUSTOM, ML
    rule_version: string
    threat_id: string
    threat_name: string
    threat_status: string
    detection_fields: Array(Tuple(name String, value String))
    alert_state: Enum8        # NEW, IN_PROGRESS, CLOSED
    url_back_to_product: string
    about {
        ip: Array(IPv6)
        hostname: string
        url: string
        file { ... }
        user { ... }
    }
}
```

### 5. Metadata (메타데이터)

이벤트 메타정보입니다.

```
metadata {
    event_timestamp: DateTime64(3, 'UTC')  # 이벤트 발생 시간
    collected_timestamp: DateTime64(3, 'UTC')  # 수집 시간
    ingestion_timestamp: DateTime64(3, 'UTC')  # 적재 시간
    event_type: Enum16        # 이벤트 카테고리
    vendor_name: string       # 벤더명
    product_name: string      # 제품명
    product_version: string   # 버전
    product_event_type: string  # 원본 이벤트 유형
    description: string       # 설명
    log_type: string          # 로그 유형
    base_labels: Map(String, String)  # 기본 라벨
    enrichment_labels: Map(String, String)  # 보강 라벨
}
```

## 필드 타입 명세

### IP 주소

```sql
-- IPv4와 IPv6 모두 지원
-- IPv4는 IPv6 매핑 형식으로 저장 (::ffff:192.168.1.1)
Array(IPv6)
```

### 타임스탬프

```sql
-- 밀리초 정밀도, UTC 타임존
DateTime64(3, 'UTC')
```

### Enum 타입

```sql
-- 이벤트 유형
Enum16('GENERIC_EVENT' = 0, 'NETWORK_CONNECTION' = 100, ...)

-- 심각도
Enum8('UNKNOWN' = 0, 'LOW' = 1, 'MEDIUM' = 2, 'HIGH' = 3, 'CRITICAL' = 4)

-- 방향
Enum8('UNKNOWN' = 0, 'INBOUND' = 1, 'OUTBOUND' = 2)

-- 플랫폼
Enum8('UNKNOWN' = 0, 'WINDOWS' = 1, 'LINUX' = 2, 'MAC' = 3, 'ANDROID' = 4, 'IOS' = 5)

-- 동작
Enum8('UNKNOWN' = 0, 'ALLOW' = 1, 'BLOCK' = 2, 'QUARANTINE' = 3, 'CHALLENGE' = 4)
```

## 인덱스 전략

### 정렬 키 (Primary Key)

```sql
ORDER BY (tenant_id, event_type, timestamp, sipHash64(event_id))
```

- `tenant_id`: 멀티테넌트 격리
- `event_type`: 이벤트 유형별 쿼리 최적화
- `timestamp`: 시계열 쿼리 지원
- `sipHash64(event_id)`: 동일 시간대 이벤트 분산

### 보조 인덱스

```sql
-- Bloom Filter 인덱스 (정확 매칭)
INDEX idx_src_ip principal_ip TYPE bloom_filter GRANULARITY 4
INDEX idx_dst_ip target_ip TYPE bloom_filter GRANULARITY 4
INDEX idx_hash_sha256 target_file_sha256 TYPE bloom_filter GRANULARITY 4

-- 세트 인덱스 (범위 쿼리)
INDEX idx_severity security_result_severity TYPE set(100) GRANULARITY 4

-- 토큰 인덱스 (부분 문자열 검색)
INDEX idx_cmdline principal_process_command_line TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
```

## 파티셔닝 전략

```sql
PARTITION BY toYYYYMMDD(timestamp)
```

- 일별 파티션
- 90일 TTL (자동 삭제)
- 효율적인 데이터 정리 및 조회

## 압축

```sql
SETTINGS
    min_bytes_for_wide_part = 10485760,
    min_rows_for_wide_part = 0
```

- ZSTD 압축 (레벨 3)
- 컬럼별 LZ4 압축 (빈번한 쿼리 대상)

## 다음 문서

- [field_mapping.md](./field_mapping.md) - 로그 소스별 필드 매핑 가이드
- [001_events.sql](../infra/clickhouse/schemas/001_events.sql) - 이벤트 테이블 DDL
