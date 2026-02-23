#!/usr/bin/env python3
"""
Kafka → ClickHouse 데이터 전송 스크립트
Kafka raw-logs 토픽에서 메시지를 읽어 ClickHouse events 테이블에 저장
"""

import json
import subprocess
import sys
from datetime import datetime

def read_kafka_messages(max_messages=50):
    """Kafka에서 메시지 읽기"""
    result = subprocess.run([
        'docker', 'exec', 'siem-kafka-dev',
        'kafka-console-consumer.sh',
        '--bootstrap-server', 'localhost:9092',
        '--topic', 'raw-logs',
        '--from-beginning',
        '--max-messages', str(max_messages),
        '--timeout-ms', '10000'
    ], capture_output=True, text=True)

    messages = [m for m in result.stdout.strip().split('\n') if m]
    return messages

def parse_message(msg):
    """Kafka 메시지를 이벤트 목록으로 변환"""
    events = []
    try:
        data = json.loads(msg)
        payload = data.get('payload', {})
        logs = payload.get('logs', [])
        source_type = payload.get('source_type', 'unknown')

        for log in logs:
            meta = log.get('metadata', {})
            ts = log.get('timestamp', datetime.utcnow().isoformat())

            # Severity 매핑
            sev_map = {
                'critical': 'CRITICAL',
                'high': 'HIGH',
                'medium': 'MEDIUM',
                'low': 'LOW',
                'informational': 'INFORMATIONAL'
            }
            severity = sev_map.get(str(meta.get('severity', '')).lower(), 'UNKNOWN')

            events.append({
                'tenant_id': 'default',
                'timestamp': ts[:26] if len(ts) > 26 else ts,
                'vendor_name': source_type,
                'product_name': meta.get('asset_id', source_type),
                'principal_ip': meta.get('source_ip', meta.get('src_ip', '')),
                'target_ip': meta.get('dst_ip', ''),
                'principal_hostname': meta.get('hostname', ''),
                'principal_user_id': meta.get('username', ''),
                'principal_process_name': meta.get('process_name', ''),
                'principal_process_command_line': meta.get('command_line', '')[:200],
                'target_domain': meta.get('domain', ''),
                'security_severity': severity,
                'security_threat_name': meta.get('threat_name', meta.get('detection_name', '')),
                'mitre_tactics': [meta.get('tactic')] if meta.get('tactic') else [],
                'mitre_techniques': [meta.get('technique')] if meta.get('technique') else [],
                'raw_log': log.get('raw', '')[:800]
            })
    except Exception as e:
        print(f"Parse error: {e}", file=sys.stderr)

    return events

def escape_sql(s):
    """SQL 이스케이프"""
    if not s:
        return ''
    return str(s).replace("'", "''").replace("\\", "\\\\").replace("\n", " ")

def insert_to_clickhouse(event):
    """ClickHouse에 이벤트 삽입"""
    tactics = "[]"
    if event['mitre_tactics']:
        tactics = "['" + "','".join(event['mitre_tactics']) + "']"

    techniques = "[]"
    if event['mitre_techniques']:
        techniques = "['" + "','".join(event['mitre_techniques']) + "']"

    sql = f"""INSERT INTO siem.events
    (tenant_id, timestamp, vendor_name, product_name, principal_ip, target_ip,
     principal_hostname, principal_user_id, principal_process_name,
     principal_process_command_line, target_domain, security_severity,
     security_threat_name, mitre_tactics, mitre_techniques, raw_log)
    VALUES
    ('{escape_sql(event['tenant_id'])}',
     parseDateTimeBestEffort('{event['timestamp']}'),
     '{escape_sql(event['vendor_name'])}',
     '{escape_sql(event['product_name'])}',
     '{escape_sql(event['principal_ip'])}',
     '{escape_sql(event['target_ip'])}',
     '{escape_sql(event['principal_hostname'])}',
     '{escape_sql(event['principal_user_id'])}',
     '{escape_sql(event['principal_process_name'])}',
     '{escape_sql(event['principal_process_command_line'])}',
     '{escape_sql(event['target_domain'])}',
     '{event['security_severity']}',
     '{escape_sql(event['security_threat_name'])}',
     {tactics},
     {techniques},
     '{escape_sql(event['raw_log'])}')"""

    result = subprocess.run(
        ['docker', 'exec', 'siem-clickhouse', 'clickhouse-client', '--query', sql],
        capture_output=True, text=True
    )
    return result.returncode == 0

def main():
    print("=" * 60)
    print("Kafka → ClickHouse 데이터 전송")
    print("=" * 60)

    # Kafka에서 읽기
    print("\n[1] Kafka에서 메시지 읽는 중...")
    messages = read_kafka_messages(50)
    print(f"    읽은 메시지: {len(messages)}개")

    # 파싱
    print("\n[2] 메시지 파싱 중...")
    all_events = []
    for msg in messages:
        events = parse_message(msg)
        all_events.extend(events)
    print(f"    파싱된 이벤트: {len(all_events)}개")

    # ClickHouse 저장
    print("\n[3] ClickHouse에 저장 중...")
    success = 0
    for evt in all_events:
        if insert_to_clickhouse(evt):
            success += 1
    print(f"    저장 완료: {success}/{len(all_events)}개")

    # 확인
    print("\n[4] 저장 확인...")
    result = subprocess.run(
        ['docker', 'exec', 'siem-clickhouse', 'clickhouse-client',
         '--query', 'SELECT count() FROM siem.events'],
        capture_output=True, text=True
    )
    print(f"    총 이벤트 수: {result.stdout.strip()}개")

    print("\n" + "=" * 60)
    print("완료!")
    print("=" * 60)

if __name__ == "__main__":
    main()
