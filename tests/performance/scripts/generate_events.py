#!/usr/bin/env python3
"""
Event Generator for Performance Testing

Generates realistic security events for load testing the SIEM-SOAR platform.
Supports various output formats and rates.

Usage:
    python generate_events.py --rate 10000 --duration 60 --output kafka
    python generate_events.py --rate 1000 --duration 300 --output file --file events.jsonl
"""

import argparse
import asyncio
import hashlib
import json
import random
import string
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


# Event types and their probabilities
EVENT_TYPES = [
    ("PROCESS_LAUNCH", 0.25),
    ("NETWORK_CONNECTION", 0.30),
    ("FILE_CREATION", 0.10),
    ("FILE_MODIFICATION", 0.08),
    ("REGISTRY_MODIFICATION", 0.05),
    ("USER_LOGIN", 0.10),
    ("AUTHENTICATION_FAILURE", 0.05),
    ("DNS_QUERY", 0.05),
    ("SERVICE_START", 0.02),
]

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHTS = [0.05, 0.15, 0.30, 0.35, 0.15]

PROCESS_NAMES = [
    "cmd.exe", "powershell.exe", "python.exe", "bash", "java.exe",
    "node.exe", "chrome.exe", "svchost.exe", "explorer.exe", "notepad.exe",
    "msiexec.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
]

SUSPICIOUS_PROCESSES = [
    "mimikatz.exe", "psexec.exe", "procdump.exe", "certutil.exe",
]

DOMAINS = [
    "google.com", "microsoft.com", "github.com", "amazon.com",
    "facebook.com", "twitter.com", "linkedin.com", "cloudflare.com",
]

SUSPICIOUS_DOMAINS = [
    "malicious-c2.com", "bad-server.net", "evil-domain.org",
    "phishing-site.com", "malware-download.net",
]


@dataclass
class Event:
    """Security event data class."""

    event_id: str
    timestamp: str
    event_type: str
    severity: str
    source: dict
    destination: dict = field(default_factory=dict)
    process: dict = field(default_factory=dict)
    network: dict = field(default_factory=dict)
    file: dict = field(default_factory=dict)
    authentication: dict = field(default_factory=dict)
    dns: dict = field(default_factory=dict)
    registry: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


class EventGenerator:
    """Generates realistic security events."""

    def __init__(self, suspicious_ratio: float = 0.1):
        self.suspicious_ratio = suspicious_ratio
        self.host_pool = [f"host-{i:05d}" for i in range(1, 10001)]
        self.user_pool = [f"user{i}" for i in range(1, 1001)]
        self.ip_pool = [f"192.168.{i // 256}.{i % 256}" for i in range(1, 65025)]

    def generate(self) -> Event:
        """Generate a single random event."""
        event_type = self._weighted_choice(EVENT_TYPES)
        is_suspicious = random.random() < self.suspicious_ratio
        severity = self._get_severity(is_suspicious)

        event = Event(
            event_id=f"evt-{uuid.uuid4().hex[:16]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            severity=severity,
            source=self._generate_source(),
            metadata={"generator": "performance_test", "suspicious": is_suspicious},
        )

        # Add type-specific fields
        if event_type == "PROCESS_LAUNCH":
            event.process = self._generate_process(is_suspicious)
        elif event_type == "NETWORK_CONNECTION":
            event.destination = self._generate_destination(is_suspicious)
            event.network = self._generate_network()
        elif event_type in ("FILE_CREATION", "FILE_MODIFICATION"):
            event.file = self._generate_file()
            event.process = self._generate_process(False)
        elif event_type in ("USER_LOGIN", "AUTHENTICATION_FAILURE"):
            event.authentication = self._generate_auth(event_type)
        elif event_type == "DNS_QUERY":
            event.dns = self._generate_dns(is_suspicious)
        elif event_type == "REGISTRY_MODIFICATION":
            event.registry = self._generate_registry(is_suspicious)

        return event

    def _weighted_choice(self, choices: list[tuple[str, float]]) -> str:
        """Select from weighted choices."""
        items, weights = zip(*choices)
        return random.choices(items, weights=weights)[0]

    def _get_severity(self, is_suspicious: bool) -> str:
        """Get severity based on suspicious flag."""
        if is_suspicious:
            weights = [0.20, 0.40, 0.25, 0.10, 0.05]
        else:
            weights = SEVERITY_WEIGHTS
        return random.choices(SEVERITIES, weights=weights)[0]

    def _generate_source(self) -> dict:
        """Generate source information."""
        return {
            "ip": random.choice(self.ip_pool),
            "hostname": random.choice(self.host_pool),
            "user": random.choice(self.user_pool),
            "mac": ":".join(f"{random.randint(0, 255):02x}" for _ in range(6)),
        }

    def _generate_destination(self, is_suspicious: bool) -> dict:
        """Generate destination information."""
        if is_suspicious and random.random() < 0.7:
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            ip = random.choice(self.ip_pool)

        return {
            "ip": ip,
            "port": random.choice([22, 80, 443, 445, 3389, 8080, 8443]),
            "hostname": random.choice(
                SUSPICIOUS_DOMAINS if is_suspicious else DOMAINS
            ),
        }

    def _generate_process(self, is_suspicious: bool) -> dict:
        """Generate process information."""
        name = random.choice(
            SUSPICIOUS_PROCESSES if is_suspicious else PROCESS_NAMES
        )
        cmd = self._generate_command_line(name, is_suspicious)

        return {
            "name": name,
            "pid": random.randint(1000, 65000),
            "command_line": cmd,
            "hash": {
                "md5": hashlib.md5(name.encode()).hexdigest(),
                "sha256": hashlib.sha256(name.encode()).hexdigest(),
            },
            "parent": {
                "name": random.choice(PROCESS_NAMES),
                "pid": random.randint(1000, 65000),
            },
        }

    def _generate_command_line(self, name: str, is_suspicious: bool) -> str:
        """Generate command line."""
        if name == "powershell.exe" and is_suspicious:
            return f"powershell.exe -EncodedCommand {''.join(random.choices(string.ascii_letters, k=50))}"
        elif name == "cmd.exe":
            return f"cmd.exe /c {''.join(random.choices(string.ascii_letters + ' ', k=30))}"
        else:
            return f"{name} {''.join(random.choices(string.ascii_letters, k=20))}"

    def _generate_network(self) -> dict:
        """Generate network information."""
        return {
            "protocol": random.choice(["TCP", "UDP"]),
            "bytes_sent": random.randint(100, 1000000),
            "bytes_received": random.randint(100, 1000000),
            "direction": random.choice(["inbound", "outbound"]),
        }

    def _generate_file(self) -> dict:
        """Generate file information."""
        ext = random.choice([".exe", ".dll", ".ps1", ".bat", ".txt", ".doc"])
        name = f"file_{random.randint(1, 10000)}{ext}"

        return {
            "path": f"C:\\Users\\user\\Downloads\\{name}",
            "name": name,
            "size": random.randint(100, 10000000),
            "hash": {
                "md5": "".join(random.choices("0123456789abcdef", k=32)),
                "sha256": "".join(random.choices("0123456789abcdef", k=64)),
            },
        }

    def _generate_auth(self, event_type: str) -> dict:
        """Generate authentication information."""
        return {
            "user": f"{random.choice(self.user_pool)}@company.local",
            "type": random.choice(["interactive", "network", "service"]),
            "result": "success" if event_type == "USER_LOGIN" else "failure",
            "logon_type": random.choice([2, 3, 10]),
            "failure_reason": "invalid_password" if event_type == "AUTHENTICATION_FAILURE" else None,
        }

    def _generate_dns(self, is_suspicious: bool) -> dict:
        """Generate DNS query information."""
        domain = random.choice(
            SUSPICIOUS_DOMAINS if is_suspicious else DOMAINS
        )

        return {
            "query": domain,
            "query_type": random.choice(["A", "AAAA", "CNAME", "MX", "TXT"]),
            "response": f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "response_code": "NOERROR",
        }

    def _generate_registry(self, is_suspicious: bool) -> dict:
        """Generate registry modification information."""
        if is_suspicious:
            key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        else:
            key = f"HKCU\\SOFTWARE\\Company\\App{random.randint(1, 100)}"

        return {
            "key": key,
            "value_name": f"Value{random.randint(1, 100)}",
            "value_data": "".join(random.choices(string.ascii_letters, k=50)),
            "action": random.choice(["create", "modify", "delete"]),
        }


class OutputHandler:
    """Handles event output to various destinations."""

    def __init__(self, output_type: str, **kwargs):
        self.output_type = output_type
        self.kwargs = kwargs
        self.count = 0

    async def setup(self):
        """Setup output handler."""
        if self.output_type == "file":
            self.file = open(self.kwargs.get("file", "events.jsonl"), "w")
        elif self.output_type == "kafka":
            # Would initialize Kafka producer here
            pass

    async def write(self, event: Event):
        """Write event to output."""
        data = json.dumps(asdict(event))

        if self.output_type == "stdout":
            print(data)
        elif self.output_type == "file":
            self.file.write(data + "\n")
        elif self.output_type == "kafka":
            # Would send to Kafka here
            pass

        self.count += 1

    async def close(self):
        """Close output handler."""
        if self.output_type == "file":
            self.file.close()


async def generate_events(
    rate: int,
    duration: int,
    output_handler: OutputHandler,
    generator: EventGenerator,
):
    """Generate events at specified rate for specified duration."""
    await output_handler.setup()

    start_time = time.time()
    end_time = start_time + duration
    events_generated = 0
    interval = 1.0 / rate if rate > 0 else 0

    print(f"Starting event generation: {rate} EPS for {duration}s")

    try:
        while time.time() < end_time:
            batch_start = time.time()
            batch_size = min(rate, 1000)  # Process in batches

            for _ in range(batch_size):
                event = generator.generate()
                await output_handler.write(event)
                events_generated += 1

            # Rate limiting
            elapsed = time.time() - batch_start
            expected = batch_size / rate
            if elapsed < expected:
                await asyncio.sleep(expected - elapsed)

            # Progress update
            total_elapsed = time.time() - start_time
            if int(total_elapsed) % 10 == 0:
                actual_rate = events_generated / total_elapsed
                print(f"Progress: {events_generated} events, {actual_rate:.0f} EPS")

    except KeyboardInterrupt:
        print("\nInterrupted by user")

    await output_handler.close()

    total_time = time.time() - start_time
    actual_rate = events_generated / total_time

    print(f"\nGeneration complete:")
    print(f"  Total events: {events_generated:,}")
    print(f"  Total time: {total_time:.2f}s")
    print(f"  Actual rate: {actual_rate:.0f} EPS")
    print(f"  Target rate: {rate} EPS")


def main():
    parser = argparse.ArgumentParser(
        description="Generate security events for performance testing"
    )
    parser.add_argument(
        "--rate", type=int, default=1000, help="Events per second (default: 1000)"
    )
    parser.add_argument(
        "--duration", type=int, default=60, help="Duration in seconds (default: 60)"
    )
    parser.add_argument(
        "--output",
        choices=["stdout", "file", "kafka"],
        default="stdout",
        help="Output destination (default: stdout)",
    )
    parser.add_argument(
        "--file", type=str, default="events.jsonl", help="Output file for file mode"
    )
    parser.add_argument(
        "--kafka-brokers",
        type=str,
        default="localhost:9092",
        help="Kafka brokers for kafka mode",
    )
    parser.add_argument(
        "--kafka-topic",
        type=str,
        default="events.raw",
        help="Kafka topic for kafka mode",
    )
    parser.add_argument(
        "--suspicious-ratio",
        type=float,
        default=0.1,
        help="Ratio of suspicious events (default: 0.1)",
    )

    args = parser.parse_args()

    generator = EventGenerator(suspicious_ratio=args.suspicious_ratio)
    output_handler = OutputHandler(
        args.output,
        file=args.file,
        brokers=args.kafka_brokers,
        topic=args.kafka_topic,
    )

    asyncio.run(
        generate_events(
            rate=args.rate,
            duration=args.duration,
            output_handler=output_handler,
            generator=generator,
        )
    )


if __name__ == "__main__":
    main()
