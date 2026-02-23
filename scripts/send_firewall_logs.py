#!/usr/bin/env python3
"""
Send test Palo Alto firewall logs to the log pipeline.

Usage:
    python send_firewall_logs.py [--url URL] [--count N] [--asset ASSET_ID]

Default endpoint: http://localhost:8089/api/v1/logs/ingest
Default asset:    PA5260-01  (must exist in meta.assets)
"""

import argparse
import random
import time
from datetime import datetime

import requests

# ============================================================
# Configuration
# ============================================================

DEFAULT_URL = "http://localhost:8089/api/v1/logs/ingest"
DEFAULT_ASSET = "PA5260-01"
DEFAULT_COUNT = 10

# ============================================================
# Palo Alto log generator
# ============================================================

SRC_IPS = ["10.0.1.100", "10.0.1.101", "192.168.1.50", "172.16.0.25", "10.0.2.88"]
DST_IPS = ["8.8.8.8", "1.1.1.1", "142.250.185.206", "104.244.42.65", "52.114.128.8"]
ACTIONS = ["allow", "deny", "drop", "reset-client", "reset-both"]
APPS = ["web-browsing", "ssl", "dns", "ssh", "ftp", "smtp", "rdp", "http"]
VSYS = ["vsys1", "vsys2"]
ZONES = ["trust", "untrust", "dmz", "guest"]
IFACES = ["ethernet1/1", "ethernet1/2", "ethernet1/3"]
REASONS = ["aged-out", "tcp-fin", "tcp-rst-from-client", "policy-deny", "threat"]


def generate_palo_alto_log() -> str:
    """
    Generate a realistic Palo Alto TRAFFIC syslog line.

    Format mirrors PA-OS TRAFFIC logs:
      <SYSLOGTIMESTAMP> <HOSTNAME> <SERIAL>,TRAFFIC,end,<DATETIME>,<VSYS>,
      <EVENT_ID>,<STAGE>,<ACTION>,<SRC_ZONE>,<DST_ZONE>,<IN_IF>,<OUT_IF>,
      <RULE_NAME>,<SRC_IP>,<DST_IP>,<NAT_SRC>,<NAT_DST>,<APP>,<PROTO>,
      <SRC_PORT>,<DST_PORT>,<NAT_SRC_PORT>,<NAT_DST_PORT>,
      <BYTES_SENT>,<BYTES_RECV>,<SESSION_END_REASON>
    """
    now = datetime.now()
    ts = now.strftime("%b %d %H:%M:%S")        # syslog timestamp
    dt = now.strftime("%Y/%m/%d %H:%M:%S")    # PA time_generated

    hostname = "fw-corp-01"
    serial = "001801000001"
    src_ip = random.choice(SRC_IPS)
    dst_ip = random.choice(DST_IPS)
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 53, 22, 21, 25, 3389, 8080])
    action = random.choice(ACTIONS)
    app = random.choice(APPS)
    vsys = random.choice(VSYS)
    src_zone = "trust"
    dst_zone = "untrust"
    in_if = random.choice(IFACES)
    out_if = random.choice(IFACES)
    rule_name = f"allow-rule-{random.randint(1, 20)}"
    event_id = f"event-{random.randint(1000, 9999)}"
    bytes_sent = random.randint(100, 50_000)
    bytes_recv = random.randint(100, 100_000)
    reason = random.choice(REASONS)

    return (
        f"{ts} {hostname} {serial},TRAFFIC,end,{dt},{vsys},{event_id},"
        f"aged-out,{action},{src_zone},{dst_zone},{in_if},{out_if},{rule_name},"
        f"{src_ip},{dst_ip},{src_ip},{dst_ip},{app},tcp,"
        f"{src_port},{dst_port},{src_port},{dst_port},"
        f"{bytes_sent},{bytes_recv},{reason}"
    )

# ============================================================
# Main
# ============================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Send test Palo Alto logs to the pipeline")
    p.add_argument("--url", default=DEFAULT_URL, help="Pipeline ingest endpoint")
    p.add_argument("--asset", default=DEFAULT_ASSET, help="Asset ID to use")
    p.add_argument("--count", type=int, default=DEFAULT_COUNT, help="Number of logs to send")
    p.add_argument("--delay", type=float, default=0.3, help="Delay between requests (seconds)")
    return p.parse_args()


def main():
    args = parse_args()

    print("=" * 65)
    print("Palo Alto Firewall Log Sender")
    print("=" * 65)
    print(f"  Endpoint : {args.url}")
    print(f"  Asset ID : {args.asset}")
    print(f"  Count    : {args.count}")
    print(f"  Delay    : {args.delay}s")
    print("=" * 65)
    print()

    # Health check
    health_url = args.url.replace("/api/v1/logs/ingest", "/health")
    try:
        r = requests.get(health_url, timeout=5)
        if r.status_code == 200:
            print("[health] Pipeline service is UP")
        else:
            print(f"[health] Unexpected status {r.status_code}")
    except Exception as exc:
        print(f"[health] Could not reach service: {exc}")
        print("[warn]   Make sure log_pipeline.py is running on port 8089")
        print()

    print()
    success = 0
    fail = 0

    for i in range(1, args.count + 1):
        raw = generate_palo_alto_log()
        payload = {"asset_id": args.asset, "raw_log": raw}

        print(f"[{i:02d}/{args.count}] Sending log...")
        print(f"        raw  : {raw[:90]}...")

        try:
            resp = requests.post(args.url, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                success += 1
                print(f"        status      : SUCCESS")
                print(f"        event_id    : {data.get('event_id')}")
                print(f"        parse_ok    : {data.get('parse_success')}")
                print(f"        fields      : {data.get('parsed_fields')}")
                print(f"        kafka       : {data.get('destinations', {}).get('kafka')}")
                print(f"        clickhouse  : {data.get('destinations', {}).get('clickhouse')}")
            else:
                fail += 1
                print(f"        status      : FAILED  HTTP {resp.status_code}")
                print(f"        detail      : {resp.text[:200]}")
        except Exception as exc:
            fail += 1
            print(f"        ERROR       : {exc}")

        print()
        if i < args.count:
            time.sleep(args.delay)

    # Summary
    print("=" * 65)
    print(f"Results: {success} succeeded, {fail} failed out of {args.count} total")
    print()
    print("Verify events in ClickHouse:")
    print(
        "  docker exec siem-clickhouse clickhouse-client "
        "-u siem --password siem_password "
        "-q \"SELECT event_id, vendor_name, product_name, principal_ip, "
        "target_ip, security_action FROM siem.events "
        "ORDER BY timestamp DESC LIMIT 10\""
    )
    print("=" * 65)


if __name__ == "__main__":
    main()
