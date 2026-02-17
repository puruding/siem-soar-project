#!/usr/bin/env python3
"""
Alert Grouping 테스트를 위한 로그 생성 스크립트

동일 패턴의 로그를 대량으로 생성하여 그룹화 동작 테스트.
파이프라인: Kafka -> Normalizer -> Detection Engine -> Alert Service

사용법:
    python3 scripts/test/generate_test_logs.py [--broker BROKER] [--dry-run]
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone

try:
    from kafka import KafkaProducer
except ImportError:
    print("ERROR: 'kafka-python' 라이브러리가 없습니다. 다음 명령으로 설치하세요:")
    print("  pip install -r scripts/test/requirements.txt")
    sys.exit(1)


# 기본 Kafka 브로커 주소
DEFAULT_BROKER = "localhost:9092"
KAFKA_TOPIC = "logs.parsed"


def utc_now_minus(minutes: int = 0) -> str:
    """UTC 타임스탬프 생성 (ISO 8601)"""
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# 패턴 1: SSH Brute Force
# 그룹화 기준: target.ip (동일 서버에 대한 반복 로그인 실패)
# ---------------------------------------------------------------------------
def generate_ssh_bruteforce_logs(target_ip: str, count: int = 50) -> list:
    """
    SSH Brute Force 패턴 로그 생성.
    동일 target IP를 향한 여러 source IP의 로그인 실패 → 1개 그룹 알림 예상.
    """
    source_ips = ["192.168.1.50", "192.168.1.51", "192.168.1.52", "10.0.0.200"]
    users = ["root", "admin", "user", "test", "guest", "oracle", "postgres"]

    logs = []
    for _ in range(count):
        log = {
            "timestamp": utc_now_minus(random.randint(0, 15)),
            "source_type": "linux_auth",
            "event_type": "USER_LOGIN",
            "principal": {
                "ip": [random.choice(source_ips)],
                "hostname": f"attacker-{random.randint(1, 4)}",
                "user": {
                    "user_name": random.choice(users)
                }
            },
            "target": {
                "ip": [target_ip],
                "hostname": "server-prod-01"
            },
            "network": {
                "application_protocol": "SSH",
                "direction": "INBOUND",
                "destination_port": 22
            },
            "security_result": {
                "action": "BLOCK",
                "severity": "MEDIUM",
                "category": "authentication_failure",
                "rule_name": "ssh_bruteforce"
            },
            "metadata": {
                "vendor_name": "Linux",
                "product_name": "sshd",
                "event_id": "4625",
                "log_type": "linux_auth"
            }
        }
        logs.append(log)
    return logs


# ---------------------------------------------------------------------------
# 패턴 2: Port Scan
# 그룹화 기준: principal.ip (동일 공격자 IP에서 다양한 포트 스캔)
# ---------------------------------------------------------------------------
def generate_port_scan_logs(source_ip: str, count: int = 100) -> list:
    """
    Port Scan 패턴 로그 생성.
    동일 source IP에서 다수 목적지 포트 스캔 → 1개 그룹 알림 예상.
    """
    target_ips = [f"192.168.10.{i}" for i in range(1, 20)]
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080
    ]

    logs = []
    for _ in range(count):
        log = {
            "timestamp": utc_now_minus(random.randint(0, 10)),
            "source_type": "firewall",
            "event_type": "NETWORK_CONNECTION",
            "principal": {
                "ip": [source_ip],
                "hostname": "scanner-host"
            },
            "target": {
                "ip": [random.choice(target_ips)],
                "port": random.choice(common_ports)
            },
            "network": {
                "direction": "OUTBOUND",
                "ip_protocol": "TCP",
                "sent_bytes": 0,
                "received_bytes": 0
            },
            "security_result": {
                "action": "BLOCK",
                "severity": "HIGH",
                "category": "port_scan",
                "rule_name": "port_scan_detection"
            },
            "metadata": {
                "vendor_name": "Palo Alto",
                "product_name": "PAN-OS",
                "log_type": "firewall"
            }
        }
        logs.append(log)
    return logs


# ---------------------------------------------------------------------------
# 패턴 3: Suspicious DNS
# 그룹화 기준: network.dns.questions.name (동일 C2 도메인 반복 조회)
# ---------------------------------------------------------------------------
def generate_dns_suspicious_logs(domain: str, count: int = 30) -> list:
    """
    Suspicious DNS 패턴 로그 생성.
    여러 내부 호스트에서 동일 악성 도메인 쿼리 → 1개 그룹 알림 예상.
    """
    internal_hosts = [f"workstation-{i:02d}" for i in range(1, 8)]
    internal_ips = [f"10.1.0.{i}" for i in range(100, 107)]
    query_types = ["A", "AAAA", "MX", "TXT"]

    logs = []
    for i in range(count):
        host_idx = i % len(internal_hosts)
        log = {
            "timestamp": utc_now_minus(random.randint(0, 20)),
            "source_type": "dns",
            "event_type": "NETWORK_DNS",
            "principal": {
                "ip": [internal_ips[host_idx]],
                "hostname": internal_hosts[host_idx]
            },
            "network": {
                "dns": {
                    "questions": [
                        {
                            "name": domain,
                            "type": random.choice(query_types)
                        }
                    ],
                    "response_code": "NOERROR" if random.random() > 0.3 else "NXDOMAIN"
                },
                "direction": "OUTBOUND",
                "application_protocol": "DNS"
            },
            "security_result": {
                "action": "ALLOW",
                "severity": "HIGH",
                "category": "c2_communication",
                "rule_name": "suspicious_dns_query"
            },
            "metadata": {
                "vendor_name": "Cisco",
                "product_name": "Umbrella",
                "log_type": "dns"
            }
        }
        logs.append(log)
    return logs


# ---------------------------------------------------------------------------
# 패턴 4: Malware Detection
# 그룹화 기준: target.file.sha256 (동일 악성 파일 해시 반복 탐지)
# ---------------------------------------------------------------------------
def generate_malware_detection_logs(file_sha256: str, count: int = 20) -> list:
    """
    Malware Detection 패턴 로그 생성.
    동일 악성 파일 해시가 여러 엔드포인트에서 발견 → 1개 그룹 알림 예상.
    """
    hosts = [f"endpoint-{i:02d}" for i in range(1, 6)]
    host_ips = [f"172.16.0.{i}" for i in range(10, 15)]
    malware_names = ["Emotet", "TrickBot", "Ryuk", "WannaCry"]
    file_name = "malicious_payload.exe"

    logs = []
    for i in range(count):
        host_idx = i % len(hosts)
        log = {
            "timestamp": utc_now_minus(random.randint(0, 30)),
            "source_type": "edr",
            "event_type": "FILE_CREATION",
            "principal": {
                "ip": [host_ips[host_idx]],
                "hostname": hosts[host_idx],
                "user": {
                    "user_name": f"user{host_idx + 1:02d}"
                }
            },
            "target": {
                "file": {
                    "full_path": f"C:\\Users\\user{host_idx + 1:02d}\\Downloads\\{file_name}",
                    "file_name": file_name,
                    "sha256": file_sha256,
                    "size": random.randint(102400, 512000)
                }
            },
            "security_result": {
                "action": "QUARANTINE",
                "severity": "CRITICAL",
                "category": "malware",
                "rule_name": "malware_file_hash",
                "threat_name": random.choice(malware_names)
            },
            "metadata": {
                "vendor_name": "CrowdStrike",
                "product_name": "Falcon",
                "log_type": "edr"
            }
        }
        logs.append(log)
    return logs


# ---------------------------------------------------------------------------
# 패턴 5: Data Exfiltration
# 그룹화 기준: principal.user.user_name + target.ip (동일 사용자의 대량 외부 전송)
# ---------------------------------------------------------------------------
def generate_data_exfiltration_logs(user: str, dest_ip: str, count: int = 20) -> list:
    """
    Data Exfiltration 패턴 로그 생성.
    동일 사용자가 동일 외부 IP로 반복 대량 전송 → 1개 그룹 알림 예상.
    """
    src_ips = ["192.168.5.50", "192.168.5.51"]
    dest_ports = [443, 8443, 9000]
    protocols = ["HTTPS", "SFTP", "FTP"]

    logs = []
    for i in range(count):
        bytes_sent = random.randint(5_000_000, 50_000_000)  # 5MB ~ 50MB
        log = {
            "timestamp": utc_now_minus(random.randint(0, 60)),
            "source_type": "dlp",
            "event_type": "NETWORK_CONNECTION",
            "principal": {
                "ip": [random.choice(src_ips)],
                "hostname": "finance-workstation",
                "user": {
                    "user_name": user,
                    "email_addresses": [f"{user}@company.internal"]
                }
            },
            "target": {
                "ip": [dest_ip],
                "hostname": "external-server",
                "port": random.choice(dest_ports)
            },
            "network": {
                "direction": "OUTBOUND",
                "application_protocol": random.choice(protocols),
                "sent_bytes": bytes_sent,
                "received_bytes": random.randint(1000, 5000)
            },
            "security_result": {
                "action": "ALLOW",
                "severity": "HIGH",
                "category": "data_exfiltration",
                "rule_name": "large_outbound_transfer"
            },
            "metadata": {
                "vendor_name": "Symantec",
                "product_name": "DLP",
                "log_type": "dlp"
            }
        }
        logs.append(log)
    return logs


# ---------------------------------------------------------------------------
# 전송 함수
# ---------------------------------------------------------------------------
def send_logs(
    logs: list,
    broker: str = DEFAULT_BROKER,
    dry_run: bool = False
) -> dict:
    """
    Kafka topic 'logs.raw' 로 로그 전송.
    각 로그는 개별 Kafka 메시지로 전송됨.
    """
    if dry_run:
        print(f"    [DRY-RUN] Kafka topic: {KAFKA_TOPIC} @ {broker}")
        print(f"    [DRY-RUN] 로그 샘플 (첫 번째):")
        print(f"    {json.dumps(logs[0], ensure_ascii=False, indent=6)}")
        return {"status": "dry_run", "count": len(logs)}

    try:
        producer = KafkaProducer(
            bootstrap_servers=broker,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        for log in logs:
            producer.send(KAFKA_TOPIC, value=log)
        producer.flush()
        producer.close()
        return {"status": "ok", "count": len(logs)}
    except Exception as e:
        return {"status": "error", "error": str(e), "count": len(logs)}


def print_result(label: str, result: dict) -> None:
    """전송 결과 출력"""
    count = result.get("count", 0)
    status = result.get("status")

    if status == "ok":
        print(f"    OK - {count}개 로그 Kafka 전송 완료")
    elif status == "dry_run":
        print(f"    DRY-RUN - {count}개 로그 (실제 전송 없음)")
    else:
        error = result.get("error", "알 수 없는 오류")
        print(f"    FAIL - {error}")


# ---------------------------------------------------------------------------
# 메인
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Alert Grouping 테스트용 로그 생성 및 Kafka 전송 스크립트"
    )
    parser.add_argument(
        "--broker",
        default=DEFAULT_BROKER,
        help=f"Kafka 브로커 주소 (기본값: {DEFAULT_BROKER})"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="실제 전송 없이 생성 로그만 출력"
    )
    parser.add_argument(
        "--pattern",
        choices=["all", "ssh", "portscan", "dns", "malware", "exfil"],
        default="all",
        help="테스트할 패턴 선택 (기본값: all)"
    )
    args = parser.parse_args()

    broker = args.broker
    dry_run = args.dry_run

    print("=" * 60)
    print("  Alert Grouping Test Log Generator")
    print("=" * 60)
    print(f"  Kafka Broker  : {broker}")
    print(f"  Topic         : {KAFKA_TOPIC}")
    print(f"  Mode          : {'DRY-RUN (전송 없음)' if dry_run else '실제 전송'}")
    print(f"  Pattern       : {args.pattern}")
    print("=" * 60)

    results = {}

    # 패턴 1: SSH Brute Force (50 events → 1 grouped alert)
    if args.pattern in ("all", "ssh"):
        print("\n[1] SSH Brute Force 로그 생성 중...")
        print("    기준: target.ip=192.168.1.100 (50개 이벤트 → 1개 그룹 알림 예상)")
        logs = generate_ssh_bruteforce_logs("192.168.1.100", count=50)
        result = send_logs(logs, broker=broker, dry_run=dry_run)
        print_result("SSH Brute Force", result)
        results["ssh_bruteforce"] = result
        if not dry_run:
            time.sleep(0.5)

    # 패턴 2: Port Scan (100 events → 1 grouped alert)
    if args.pattern in ("all", "portscan"):
        print("\n[2] Port Scan 로그 생성 중...")
        print("    기준: principal.ip=10.0.0.99 (100개 이벤트 → 1개 그룹 알림 예상)")
        logs = generate_port_scan_logs("10.0.0.99", count=100)
        result = send_logs(logs, broker=broker, dry_run=dry_run)
        print_result("Port Scan", result)
        results["port_scan"] = result
        if not dry_run:
            time.sleep(0.5)

    # 패턴 3: Suspicious DNS (30 events → 1 grouped alert)
    if args.pattern in ("all", "dns"):
        print("\n[3] Suspicious DNS 로그 생성 중...")
        print("    기준: dns.domain=c2.evil-domain.com (30개 이벤트 → 1개 그룹 알림 예상)")
        logs = generate_dns_suspicious_logs("c2.evil-domain.com", count=30)
        result = send_logs(logs, broker=broker, dry_run=dry_run)
        print_result("Suspicious DNS", result)
        results["suspicious_dns"] = result
        if not dry_run:
            time.sleep(0.5)

    # 패턴 4: Malware Detection (20 events → 1 grouped alert)
    if args.pattern in ("all", "malware"):
        print("\n[4] Malware Detection 로그 생성 중...")
        malware_hash = "a3f1c2e4b5d6789012345678901234567890abcdef1234567890abcdef123456"
        print(f"    기준: file.sha256={malware_hash[:16]}... (20개 이벤트 → 1개 그룹 알림 예상)")
        logs = generate_malware_detection_logs(malware_hash, count=20)
        result = send_logs(logs, broker=broker, dry_run=dry_run)
        print_result("Malware Detection", result)
        results["malware_detection"] = result
        if not dry_run:
            time.sleep(0.5)

    # 패턴 5: Data Exfiltration (20 events → 1 grouped alert)
    if args.pattern in ("all", "exfil"):
        print("\n[5] Data Exfiltration 로그 생성 중...")
        print("    기준: user=jsmith + dest_ip=203.0.113.50 (20개 이벤트 → 1개 그룹 알림 예상)")
        logs = generate_data_exfiltration_logs("jsmith", "203.0.113.50", count=20)
        result = send_logs(logs, broker=broker, dry_run=dry_run)
        print_result("Data Exfiltration", result)
        results["data_exfiltration"] = result

    # 요약
    print("\n" + "=" * 60)
    print("  전송 완료 요약")
    print("=" * 60)
    total_sent = sum(r.get("count", 0) for r in results.values())
    success = sum(
        1 for r in results.values()
        if r.get("status") in ("ok", "dry_run")
    )
    print(f"  총 로그 수  : {total_sent}개")
    print(f"  성공 패턴  : {success}/{len(results)}")
    if not dry_run:
        print()
        print("  파이프라인 처리 대기 중... (30초 후 UI에서 확인 가능)")
        print()
        print("  UI 확인: http://localhost:5173/alerts")
        print("  예상 결과: 패턴별 그룹화된 알림 목록 표시")
    print("=" * 60)


if __name__ == "__main__":
    main()
