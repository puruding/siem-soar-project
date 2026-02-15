# 필드 매핑 가이드

## 개요

이 문서는 다양한 보안 로그 소스를 SIEM-SOAR UDM으로 매핑하는 방법을 설명합니다.

## 매핑 원칙

1. **원본 보존**: 매핑 불가능한 필드는 `raw_log` 또는 `metadata.base_labels`에 보존
2. **타입 변환**: 문자열 IP → IPv6, 문자열 타임스탬프 → DateTime64
3. **정규화**: 모든 타임스탬프는 UTC로 변환
4. **확장**: 커스텀 필드는 `Map(String, String)` 타입 사용

## 공통 매핑 패턴

### 타임스탬프 변환

```
| 소스 형식 | 변환 함수 |
|----------|----------|
| Unix Epoch (초) | toDateTime64(value, 3, 'UTC') |
| Unix Epoch (밀리초) | toDateTime64(value / 1000, 3, 'UTC') |
| ISO 8601 | parseDateTimeBestEffort(value) |
| Syslog RFC 3164 | parseDateTimeBestEffortUS(value) |
| Windows FILETIME | toDateTime64((value - 116444736000000000) / 10000000, 3, 'UTC') |
```

### IP 주소 변환

```
| 소스 형식 | 변환 함수 |
|----------|----------|
| IPv4 문자열 | toIPv6(toIPv4(value)) |
| IPv6 문자열 | toIPv6(value) |
| 정수 (빅엔디안) | IPv4NumToString(value) |
```

---

## 1. Windows Event Log

### 소스 정보
- **벤더**: Microsoft
- **제품**: Windows
- **로그 채널**: Security, System, Application, Sysmon

### 로그인 이벤트 (Event ID 4624)

```yaml
UDM Field: Source Field
----------------------------------------
metadata.event_type: USER_LOGIN (상수)
metadata.event_timestamp: TimeCreated.SystemTime
metadata.vendor_name: "Microsoft"
metadata.product_name: "Windows"
metadata.product_event_type: EventID (4624)
metadata.description: "An account was successfully logged on"

principal.hostname: Computer
principal.user.userid: TargetUserName
principal.user.windows_sid: TargetUserSid
principal.administrative_domain: TargetDomainName
principal.ip: IpAddress (WorkstationName이 IP인 경우)
principal.platform: WINDOWS (상수)

target.hostname: WorkstationName (호스트명인 경우)

network.direction: INBOUND (상수, 원격 로그인)

security_result.action: ALLOW (상수)
security_result.category: "Authentication"
security_result.detection_fields: [
    ("LogonType", LogonType),
    ("LogonProcessName", LogonProcessName),
    ("AuthenticationPackageName", AuthenticationPackageName),
    ("SubjectUserName", SubjectUserName)
]
```

### Logon Type 매핑

| LogonType | 설명 | network.direction |
|-----------|------|-------------------|
| 2 | Interactive | UNKNOWN |
| 3 | Network | INBOUND |
| 4 | Batch | UNKNOWN |
| 5 | Service | UNKNOWN |
| 7 | Unlock | UNKNOWN |
| 8 | NetworkCleartext | INBOUND |
| 9 | NewCredentials | UNKNOWN |
| 10 | RemoteInteractive (RDP) | INBOUND |
| 11 | CachedInteractive | UNKNOWN |

### 프로세스 생성 (Sysmon Event ID 1)

```yaml
UDM Field: Source Field
----------------------------------------
metadata.event_type: PROCESS_LAUNCH (상수)
metadata.event_timestamp: TimeCreated.SystemTime
metadata.product_name: "Sysmon"
metadata.product_event_type: EventID (1)

principal.hostname: Computer
principal.user.userid: User (도메인\사용자에서 추출)
principal.administrative_domain: User (도메인 부분)
principal.process.pid: ProcessId
principal.process.file.full_path: Image
principal.process.file.sha256: Hashes (SHA256 추출)
principal.process.file.md5: Hashes (MD5 추출)
principal.process.command_line: CommandLine
principal.process.parent_process.pid: ParentProcessId
principal.process.parent_process.file.full_path: ParentImage
principal.process.parent_process.command_line: ParentCommandLine

target.file.full_path: CurrentDirectory

security_result.category: "Process Execution"
security_result.detection_fields: [
    ("IntegrityLevel", IntegrityLevel),
    ("TerminalSessionId", TerminalSessionId),
    ("FileVersion", FileVersion),
    ("Company", Company),
    ("Product", Product)
]
```

---

## 2. Linux Auditd

### 소스 정보
- **벤더**: Linux
- **제품**: Auditd
- **로그 형식**: key=value 쌍

### EXECVE 이벤트

```yaml
UDM Field: Source Field
----------------------------------------
metadata.event_type: PROCESS_LAUNCH (상수)
metadata.event_timestamp: msg의 타임스탬프 (audit(1234567890.123:456))
metadata.vendor_name: "Linux"
metadata.product_name: "Auditd"
metadata.product_event_type: type (EXECVE)

principal.hostname: node (node= 필드)
principal.user.userid: uid 또는 auid (숫자 → 이름 변환)
principal.process.pid: pid
principal.process.command_line: a0, a1, a2... 연결
principal.process.parent_process.pid: ppid

security_result.category: "Process Execution"
security_result.detection_fields: [
    ("ses", ses),
    ("tty", tty),
    ("comm", comm),
    ("exe", exe),
    ("key", key)
]
```

### USER_LOGIN 이벤트

```yaml
UDM Field: Source Field
----------------------------------------
metadata.event_type: USER_LOGIN (상수)
metadata.event_timestamp: msg 타임스탬프

principal.hostname: node
principal.user.userid: acct (또는 id)
principal.ip: addr (원격 IP)
principal.port: 0 (정보 없음)

security_result.action: res="success" ? ALLOW : BLOCK
security_result.category: "Authentication"
security_result.detection_fields: [
    ("terminal", terminal),
    ("exe", exe)
]
```

---

## 3. Apache/Nginx Access Log

### 소스 정보
- **벤더**: Apache/Nginx
- **제품**: HTTP Server
- **로그 형식**: Combined Log Format

### HTTP 요청

```yaml
UDM Field: Source Field (Combined Log Format)
----------------------------------------
# 형식: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
# 예시: 192.168.1.1 - john [10/Oct/2024:13:55:36 -0700] "GET /api/v1/users HTTP/1.1" 200 2326 "https://example.com" "Mozilla/5.0"

metadata.event_type: NETWORK_HTTP (상수)
metadata.event_timestamp: [10/Oct/2024:13:55:36 -0700] 파싱
metadata.vendor_name: "Apache" 또는 "Nginx"
metadata.product_name: "HTTP Server"

principal.ip: %h (클라이언트 IP)
principal.user.userid: %u (인증된 사용자, '-'이면 null)

target.hostname: 서버 호스트명
target.url: %r에서 추출 (GET /api/v1/users)

network.application_protocol: HTTP (상수)
network.direction: INBOUND (상수)
network.http.method: %r에서 추출 (GET)
network.http.response_code: %>s (200)
network.http.referral_url: Referer 헤더
network.http.user_agent: User-Agent 헤더
network.sent_bytes: %b (응답 크기)

security_result.category: "Web Access"
```

---

## 4. Firewall Logs (Palo Alto)

### 소스 정보
- **벤더**: Palo Alto Networks
- **제품**: PAN-OS
- **로그 형식**: CSV (Syslog 전송)

### Traffic Log

```yaml
UDM Field: Source Field (CSV 위치)
----------------------------------------
metadata.event_type: NETWORK_CONNECTION (상수)
metadata.event_timestamp: Receive Time (필드 1) 또는 Generated Time (필드 2)
metadata.vendor_name: "Palo Alto Networks"
metadata.product_name: "PAN-OS"
metadata.product_event_type: Type (필드 3, "TRAFFIC")

principal.ip: Source Address (필드 7)
principal.port: Source Port (필드 24)
principal.user.userid: Source User (필드 12)
principal.hostname: Source Zone에서 추론

target.ip: Destination Address (필드 8)
target.port: Destination Port (필드 25)
target.hostname: NAT Destination IP에서 추론
target.url: URL/Filename (필드 31) - URL 필터링 시

network.application_protocol: Application (필드 14)에서 매핑
network.direction: Flags (필드 34)에서 추론
network.ip_protocol: Protocol (필드 29)에서 매핑 (tcp=6, udp=17)
network.received_bytes: Bytes Received (필드 49)
network.sent_bytes: Bytes Sent (필드 48)
network.session_duration: Elapsed Time (필드 47)
network.session_id: Session ID (필드 53)

security_result.action: Action (필드 32)
    - "allow" → ALLOW
    - "deny" → BLOCK
    - "drop" → BLOCK
    - "reset-client" → BLOCK
security_result.category: Category (필드 35)
security_result.rule_name: Rule (필드 11)
```

---

## 5. AWS CloudTrail

### 소스 정보
- **벤더**: Amazon Web Services
- **제품**: CloudTrail
- **로그 형식**: JSON

### API 호출 이벤트

```yaml
UDM Field: Source Field (JSON 경로)
----------------------------------------
metadata.event_type: 이벤트명에 따라 동적 결정
    - "ConsoleLogin" → USER_LOGIN
    - "CreateUser" → USER_CREATION
    - "RunInstances" → RESOURCE_CREATION
    - 기타 → GENERIC_EVENT
metadata.event_timestamp: eventTime
metadata.vendor_name: "AWS"
metadata.product_name: eventSource (예: ec2.amazonaws.com → EC2)
metadata.product_event_type: eventName

principal.user.userid: userIdentity.userName 또는 userIdentity.principalId
principal.user.user_display_name: userIdentity.arn
principal.ip: sourceIPAddress
principal.administrative_domain: userIdentity.accountId

target.resource.name: requestParameters에서 추출 (이벤트별 다름)
target.resource.type: eventSource에서 추출
target.resource.id: responseElements에서 추출

security_result.action: errorCode 없으면 ALLOW, 있으면 BLOCK
security_result.category: "AWS API"
security_result.detection_fields: [
    ("eventType", eventType),
    ("awsRegion", awsRegion),
    ("userAgent", userAgent),
    ("errorCode", errorCode),
    ("errorMessage", errorMessage)
]

metadata.base_labels: {
    "aws_account_id": userIdentity.accountId,
    "aws_region": awsRegion,
    "event_id": eventID,
    "request_id": requestID
}
```

---

## 6. EDR (CrowdStrike Falcon)

### 소스 정보
- **벤더**: CrowdStrike
- **제품**: Falcon
- **로그 형식**: JSON (Streaming API)

### Detection Event

```yaml
UDM Field: Source Field
----------------------------------------
metadata.event_type:
    - ProcessRollup → PROCESS_LAUNCH
    - NetworkConnect → NETWORK_CONNECTION
    - DetectionSummary → ALERT
metadata.event_timestamp: timestamp (Unix milliseconds)
metadata.vendor_name: "CrowdStrike"
metadata.product_name: "Falcon"
metadata.product_event_type: event_simpleName

principal.hostname: ComputerName
principal.ip: LocalAddressIP4 또는 LocalAddressIP6
principal.user.userid: UserName
principal.user.windows_sid: UserSid
principal.process.pid: ContextProcessId
principal.process.file.full_path: FileName
principal.process.file.sha256: SHA256HashData
principal.process.file.md5: MD5HashData
principal.process.command_line: CommandLine
principal.process.parent_process.pid: ParentProcessId
principal.process.parent_process.file.full_path: ParentImageFileName
principal.platform: platform_name에서 매핑

target.ip: RemoteAddressIP4 또는 RemoteAddressIP6
target.port: RemotePort

network.direction: NetworkDirection ("1" → INBOUND, "2" → OUTBOUND)
network.ip_protocol: Protocol에서 매핑

security_result.severity: Severity에서 매핑
    - 1 → LOW
    - 2 → MEDIUM
    - 3 → HIGH
    - 4 → CRITICAL
security_result.confidence: Confidence / 100
security_result.threat_name: DetectName
security_result.threat_id: DetectId
security_result.category: Tactic
security_result.category_details: Technique 배열
security_result.url_back_to_product: FalconHostLink
```

---

## 7. Splunk (Forwarded Events)

Splunk에서 전달받은 이벤트의 경우, 원본 로그 형식에 따라 위 매핑을 적용합니다.
Splunk 메타데이터는 다음과 같이 보존합니다:

```yaml
metadata.base_labels: {
    "splunk_index": index,
    "splunk_sourcetype": sourcetype,
    "splunk_source": source,
    "splunk_host": host,
    "splunk_time": _time
}
```

---

## 매핑 유효성 검사

### 필수 필드 체크

```go
func ValidateUDMEvent(event *UDMEvent) error {
    if event.Metadata.EventTimestamp.IsZero() {
        return errors.New("event_timestamp is required")
    }
    if event.Metadata.EventType == 0 {
        return errors.New("event_type is required")
    }
    if event.Metadata.VendorName == "" {
        return errors.New("vendor_name is required")
    }
    if event.Metadata.ProductName == "" {
        return errors.New("product_name is required")
    }
    return nil
}
```

### 타입 변환 유틸리티

```go
// IPv4 문자열을 IPv6로 변환
func IPv4ToIPv6(ipv4 string) net.IP {
    ip := net.ParseIP(ipv4)
    if ip == nil {
        return nil
    }
    return ip.To16()
}

// 유닉스 타임스탬프를 DateTime64로 변환
func UnixMillisToDateTime(ms int64) time.Time {
    return time.UnixMilli(ms).UTC()
}
```

---

## 다음 단계

1. 각 로그 소스별 파서 구현 (`/services/parser/`)
2. 정규화 로직 구현 (`/services/normalizer/`)
3. 매핑 룰 설정 파일 (`/config/mappings/`)
