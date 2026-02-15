"""Korean security domain dataset for fine-tuning."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class TaskType(str, Enum):
    """Task types for security domain."""

    SUMMARIZATION = "summarization"
    NL2SQL = "nl2sql"
    CLASSIFICATION = "classification"
    QA = "qa"
    TRANSLATION = "translation"  # Security term translation
    EXPLANATION = "explanation"


class DatasetConfig(BaseModel):
    """Configuration for dataset creation."""

    task_types: list[TaskType] = Field(default_factory=lambda: list(TaskType))
    language: str = Field(default="ko", description="Primary language")
    include_english: bool = Field(default=True, description="Include bilingual examples")
    train_ratio: float = Field(default=0.9, ge=0, le=1)
    seed: int = Field(default=42)
    max_examples_per_task: int | None = Field(default=None)


@dataclass
class TrainingExample:
    """Single training example."""

    task_type: TaskType
    instruction: str
    input_text: str
    output_text: str
    metadata: dict[str, Any] = field(default_factory=dict)


class SecurityDataset(LoggerMixin):
    """Dataset for Korean security domain fine-tuning.

    Features:
    - Korean security terminology
    - Multi-task examples (summarization, NL2SQL, QA)
    - Bilingual support (Korean/English)
    - Data augmentation
    """

    # Korean security terminology mapping
    SECURITY_TERMS_KO = {
        # Alert/Incident terms
        "alert": "경보",
        "incident": "인시던트",
        "event": "이벤트",
        "threat": "위협",
        "vulnerability": "취약점",
        "attack": "공격",
        "breach": "침해",
        "intrusion": "침입",

        # Severity
        "critical": "심각",
        "high": "높음",
        "medium": "중간",
        "low": "낮음",

        # Actions
        "investigate": "조사",
        "analyze": "분석",
        "respond": "대응",
        "mitigate": "완화",
        "remediate": "복구",
        "contain": "격리",
        "eradicate": "제거",

        # Technical terms
        "malware": "악성코드",
        "ransomware": "랜섬웨어",
        "phishing": "피싱",
        "brute force": "무차별 대입",
        "lateral movement": "측면 이동",
        "privilege escalation": "권한 상승",
        "data exfiltration": "데이터 유출",
        "command and control": "명령 및 제어",
        "indicator of compromise": "침해 지표",
        "tactics techniques procedures": "전술 기술 절차",

        # Network
        "firewall": "방화벽",
        "endpoint": "엔드포인트",
        "network traffic": "네트워크 트래픽",
        "packet": "패킷",

        # Reports
        "summary": "요약",
        "report": "보고서",
        "timeline": "타임라인",
        "recommendation": "권장사항",
    }

    def __init__(self, config: DatasetConfig | None = None) -> None:
        """Initialize the dataset.

        Args:
            config: Dataset configuration
        """
        self.config = config or DatasetConfig()
        self._examples: list[TrainingExample] = []
        random.seed(self.config.seed)

    def load_from_file(self, filepath: str) -> int:
        """Load examples from JSON/JSONL file.

        Args:
            filepath: Path to data file

        Returns:
            Number of examples loaded
        """
        path = Path(filepath)
        count = 0

        if path.suffix == ".jsonl":
            with open(path, encoding="utf-8") as f:
                for line in f:
                    data = json.loads(line)
                    self._examples.append(self._parse_example(data))
                    count += 1
        elif path.suffix == ".json":
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    self._examples.append(self._parse_example(item))
                    count += 1

        self.logger.info("loaded_examples", filepath=filepath, count=count)
        return count

    def _parse_example(self, data: dict[str, Any]) -> TrainingExample:
        """Parse example from dict."""
        return TrainingExample(
            task_type=TaskType(data.get("task_type", "qa")),
            instruction=data.get("instruction", ""),
            input_text=data.get("input", ""),
            output_text=data.get("output", ""),
            metadata=data.get("metadata", {}),
        )

    def add_example(self, example: TrainingExample) -> None:
        """Add a training example."""
        self._examples.append(example)

    def generate_synthetic_examples(self) -> int:
        """Generate synthetic training examples.

        Returns:
            Number of examples generated
        """
        count = 0

        # Summarization examples
        if TaskType.SUMMARIZATION in self.config.task_types:
            count += self._generate_summarization_examples()

        # NL2SQL examples
        if TaskType.NL2SQL in self.config.task_types:
            count += self._generate_nl2sql_examples()

        # QA examples
        if TaskType.QA in self.config.task_types:
            count += self._generate_qa_examples()

        # Classification examples
        if TaskType.CLASSIFICATION in self.config.task_types:
            count += self._generate_classification_examples()

        self.logger.info("generated_synthetic", count=count)
        return count

    def _generate_summarization_examples(self) -> int:
        """Generate summarization examples."""
        templates = [
            {
                "instruction": "다음 보안 인시던트를 한국어로 요약하세요.",
                "input": "Critical alert detected: Multiple failed SSH login attempts from IP {ip} targeting server {server}. Total attempts: {count} over {duration}. Source appears to be automated attack tool.",
                "output": "심각한 경보가 감지되었습니다. IP {ip}에서 서버 {server}를 대상으로 다수의 SSH 로그인 실패 시도가 발생했습니다. {duration} 동안 총 {count}번의 시도가 있었으며, 자동화된 공격 도구로 추정됩니다.",
            },
            {
                "instruction": "보안 이벤트 요약을 작성하세요.",
                "input": "Malware detected on workstation {host}. File hash: {hash}. Detection: {detection}. The malware attempted to establish connection to external IP {c2_ip}.",
                "output": "워크스테이션 {host}에서 악성코드가 탐지되었습니다. 파일 해시: {hash}, 탐지명: {detection}. 악성코드는 외부 IP {c2_ip}와의 연결을 시도했습니다.",
            },
            {
                "instruction": "인시던트 대응 보고서 요약을 작성하세요.",
                "input": "Phishing campaign targeting finance department. {recipients} users received malicious emails. {clicked} users clicked the link. {compromised} accounts potentially compromised.",
                "output": "재무부서를 대상으로 한 피싱 캠페인이 발생했습니다. {recipients}명의 사용자가 악성 이메일을 수신했으며, {clicked}명이 링크를 클릭했습니다. {compromised}개 계정이 잠재적으로 침해되었을 수 있습니다.",
            },
        ]

        count = 0
        for template in templates:
            # Generate variations
            for _ in range(10):
                params = {
                    "ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    "server": f"srv-{random.randint(1,100):03d}",
                    "count": random.randint(100, 10000),
                    "duration": f"{random.randint(1, 24)}시간",
                    "host": f"WS-{random.randint(1000, 9999)}",
                    "hash": f"{''.join(random.choices('0123456789abcdef', k=32))}",
                    "detection": random.choice(["Trojan.GenericKD", "Emotet.A", "Ryuk.B"]),
                    "c2_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "recipients": random.randint(10, 500),
                    "clicked": random.randint(1, 50),
                    "compromised": random.randint(0, 10),
                }

                self.add_example(TrainingExample(
                    task_type=TaskType.SUMMARIZATION,
                    instruction=template["instruction"],
                    input_text=template["input"].format(**params),
                    output_text=template["output"].format(**params),
                ))
                count += 1

        return count

    def _generate_nl2sql_examples(self) -> int:
        """Generate NL2SQL examples."""
        templates = [
            {
                "ko": "오늘 발생한 심각한 경보를 보여주세요",
                "sql": "SELECT * FROM alerts WHERE severity = 'critical' AND created_at >= today() ORDER BY created_at DESC",
            },
            {
                "ko": "지난 1시간 동안의 이벤트 수를 알려주세요",
                "sql": "SELECT COUNT(*) FROM events WHERE timestamp > now() - INTERVAL 1 HOUR",
            },
            {
                "ko": "가장 많은 이벤트를 발생시킨 IP 주소 상위 10개는?",
                "sql": "SELECT source_ip, COUNT(*) as cnt FROM events GROUP BY source_ip ORDER BY cnt DESC LIMIT 10",
            },
            {
                "ko": "이번 주 심각도별 경보 수를 알려주세요",
                "sql": "SELECT severity, COUNT(*) FROM alerts WHERE created_at >= today() - 7 GROUP BY severity",
            },
            {
                "ko": "{user} 사용자에게 할당된 케이스를 조회해주세요",
                "sql": "SELECT * FROM cases WHERE assignee_id = (SELECT user_id FROM users WHERE username = '{user}')",
            },
            {
                "ko": "포트 {port}로의 네트워크 트래픽을 보여주세요",
                "sql": "SELECT * FROM events WHERE dest_port = {port} AND timestamp > now() - INTERVAL 1 HOUR ORDER BY timestamp DESC",
            },
            {
                "ko": "악성코드 탐지 이벤트 중 측면 이동이 의심되는 것은?",
                "sql": "SELECT * FROM events WHERE event_type = 'malware' AND parsed_data LIKE '%lateral%' ORDER BY timestamp DESC",
            },
            {
                "ko": "인증 실패가 100회 이상인 IP 주소를 찾아주세요",
                "sql": "SELECT source_ip, COUNT(*) as failures FROM events WHERE event_type = 'authentication' AND status = 'failed' GROUP BY source_ip HAVING failures > 100",
            },
        ]

        count = 0
        for template in templates:
            params = {
                "user": random.choice(["admin", "analyst1", "soc_lead"]),
                "port": random.choice([22, 80, 443, 3389, 8080]),
            }

            self.add_example(TrainingExample(
                task_type=TaskType.NL2SQL,
                instruction="자연어 질문을 SQL 쿼리로 변환하세요.",
                input_text=template["ko"].format(**params),
                output_text=template["sql"].format(**params),
            ))
            count += 1

        return count

    def _generate_qa_examples(self) -> int:
        """Generate QA examples."""
        qa_pairs = [
            {
                "q": "랜섬웨어 공격을 받았을 때 첫 번째로 해야 할 일은 무엇인가요?",
                "a": "랜섬웨어 공격 시 첫 번째로 해야 할 일은 감염된 시스템을 네트워크에서 즉시 격리하는 것입니다. 이렇게 하면 추가 확산을 방지하고 다른 시스템을 보호할 수 있습니다.",
            },
            {
                "q": "MITRE ATT&CK이란 무엇인가요?",
                "a": "MITRE ATT&CK은 사이버 공격자의 행동을 설명하는 전술, 기술 및 절차(TTP)의 글로벌 지식 기반입니다. 보안 팀이 위협을 이해하고 방어 체계를 강화하는 데 활용됩니다.",
            },
            {
                "q": "침해 지표(IOC)에는 어떤 종류가 있나요?",
                "a": "주요 침해 지표(IOC)에는 악성 IP 주소, 악성 도메인, 파일 해시(MD5, SHA256), 악성 URL, 이메일 주소, 레지스트리 키, 파일 경로 등이 있습니다.",
            },
            {
                "q": "피싱 이메일을 어떻게 식별하나요?",
                "a": "피싱 이메일 식별 방법: 1) 발신자 주소 확인 2) 긴급함을 강조하는 문구 주의 3) 의심스러운 링크 URL 확인 4) 첨부파일 주의 5) 문법/맞춤법 오류 확인 6) 개인정보 요청 의심",
            },
            {
                "q": "권한 상승 공격이란 무엇인가요?",
                "a": "권한 상승 공격은 공격자가 일반 사용자 권한에서 시작하여 시스템 또는 관리자 권한을 획득하는 공격입니다. 취약점 악용, 잘못된 설정, 자격 증명 탈취 등의 방법이 사용됩니다.",
            },
        ]

        count = 0
        for qa in qa_pairs:
            self.add_example(TrainingExample(
                task_type=TaskType.QA,
                instruction="다음 보안 관련 질문에 답변하세요.",
                input_text=qa["q"],
                output_text=qa["a"],
            ))
            count += 1

        return count

    def _generate_classification_examples(self) -> int:
        """Generate classification examples."""
        examples = [
            {
                "text": "Multiple failed SSH login attempts detected from external IP",
                "label": "brute_force",
                "label_ko": "무차별 대입 공격",
            },
            {
                "text": "Suspicious PowerShell script execution with encoded command",
                "label": "malware",
                "label_ko": "악성코드",
            },
            {
                "text": "User reported receiving email asking for credentials",
                "label": "phishing",
                "label_ko": "피싱",
            },
            {
                "text": "Large data transfer to external IP address detected",
                "label": "data_exfiltration",
                "label_ko": "데이터 유출",
            },
            {
                "text": "Unusual process spawning from Microsoft Office application",
                "label": "malware",
                "label_ko": "악성코드",
            },
        ]

        count = 0
        for ex in examples:
            self.add_example(TrainingExample(
                task_type=TaskType.CLASSIFICATION,
                instruction="다음 보안 이벤트의 유형을 분류하세요.",
                input_text=ex["text"],
                output_text=f"{ex['label']} ({ex['label_ko']})",
            ))
            count += 1

        return count

    def get_train_test_split(self) -> tuple[list[TrainingExample], list[TrainingExample]]:
        """Split dataset into train and test sets.

        Returns:
            Tuple of (train_examples, test_examples)
        """
        examples = self._examples.copy()
        random.shuffle(examples)

        split_idx = int(len(examples) * self.config.train_ratio)
        return examples[:split_idx], examples[split_idx:]

    def __len__(self) -> int:
        """Return number of examples."""
        return len(self._examples)

    def __iter__(self) -> Iterator[TrainingExample]:
        """Iterate over examples."""
        return iter(self._examples)

    def to_chat_format(self) -> list[dict[str, Any]]:
        """Convert to chat format for training.

        Returns:
            List of chat-formatted examples
        """
        formatted = []

        for example in self._examples:
            formatted.append({
                "messages": [
                    {"role": "system", "content": "당신은 보안 분석 전문가입니다."},
                    {"role": "user", "content": f"{example.instruction}\n\n{example.input_text}"},
                    {"role": "assistant", "content": example.output_text},
                ],
                "task_type": example.task_type.value,
            })

        return formatted

    def save_to_file(self, filepath: str, format: str = "jsonl") -> None:
        """Save dataset to file.

        Args:
            filepath: Output file path
            format: Output format (jsonl or json)
        """
        data = self.to_chat_format()

        with open(filepath, "w", encoding="utf-8") as f:
            if format == "jsonl":
                for item in data:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")
            else:
                json.dump(data, f, ensure_ascii=False, indent=2)

        self.logger.info("saved_dataset", filepath=filepath, count=len(data))


def create_security_dataset(config: DatasetConfig | None = None) -> SecurityDataset:
    """Create and populate a security dataset.

    Args:
        config: Dataset configuration

    Returns:
        Populated SecurityDataset
    """
    dataset = SecurityDataset(config)
    dataset.generate_synthetic_examples()
    return dataset
