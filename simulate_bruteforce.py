import time
import json
import requests
import datetime
import random

# Configuration
COLLECTOR_URL = "http://localhost:8087/api/v1/logs"
EPS = 10  # Events per second
TARGET_ASSET_IP = "10.0.0.50" # 1개 자산 선택 (예: 웹서버 또는 DB 서버)
SOURCE_IP = "192.168.1.100"   # 공격자 IP

def generate_log():
    return {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "event_type": "authentication",
        "action": "failed",
        "application": "sshd",
        "message": f"Failed password for invalid user admin from {SOURCE_IP} port {random.randint(10000, 60000)} ssh2",
        "target": {
            "ip": TARGET_ASSET_IP
        },
        "source": {
            "ip": SOURCE_IP
        }
    }

def main():
    print(f"Starting Log Generator at {EPS} EPS...")
    print(f"Target Asset IP: {TARGET_ASSET_IP}")
    print(f"Destination: {COLLECTOR_URL}")
    print("Press Ctrl+C to stop.")
    
    headers = {"Content-Type": "application/json"}
    
    try:
        while True:
            # 1초에 보낼 10개의 로그를 생성
            logs = [generate_log() for _ in range(EPS)]
            
            try:
                response = requests.post(COLLECTOR_URL, json=logs, headers=headers)
                if response.status_code in (200, 202):
                    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Sent {EPS} logs successfully.")
                else:
                    print(f"Failed to send logs. Status: {response.status_code}, Body: {response.text}")
            except Exception as e:
                print(f"Connection error: {e}")
            
            # 1초 대기
            time.sleep(1.0)
            
    except KeyboardInterrupt:
        print("\nLog generation stopped by user.")

if __name__ == "__main__":
    main()
