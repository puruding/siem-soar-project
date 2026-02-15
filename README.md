# SIEM-SOAR Integrated Platform

Enterprise Security Information and Event Management (SIEM) with Security Orchestration, Automation, and Response (SOAR) capabilities.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Web Dashboard                                   │
│                     (React + TypeScript + TailwindCSS)                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API Gateway                                     │
│                          (Go + Authentication)                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                             │                             │
         ▼                             ▼                             ▼
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   Detection     │         │     SOAR        │         │  Threat Intel   │
│   (Go + Rules)  │         │  (Go + Temporal)│         │   (Go + Feeds)  │
└─────────────────┘         └─────────────────┘         └─────────────────┘
         │                             │                             │
         └─────────────────────────────┼─────────────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                             │                             │
         ▼                             ▼                             ▼
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   Query Engine  │         │  Case Manager   │         │    Collector    │
│ (Go + ClickHouse)│        │  (Go + Postgres)│         │  (Go + Vector)  │
└─────────────────┘         └─────────────────┘         └─────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             AI Services                                      │
│                    (Python + PyTorch + LangChain + vLLM)                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                      │
│  │   Triage    │    │   Copilot   │    │   Agentic   │                      │
│  └─────────────┘    └─────────────┘    └─────────────┘                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Data Layer                                        │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ ClickHouse  │    │  PostgreSQL │    │    Redis    │    │    Kafka    │  │
│  │   (OLAP)    │    │   (OLTP)    │    │   (Cache)   │    │ (Streaming) │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Go (Core Services), Python (AI/ML), Rust (High-performance Agent) |
| **Frontend** | React, TypeScript, TailwindCSS, Zustand |
| **Databases** | ClickHouse (OLAP), PostgreSQL (OLTP), Redis (Cache) |
| **AI/ML** | PyTorch, LangChain, vLLM |
| **Streaming** | Apache Kafka, Vector |
| **Workflow** | Temporal |
| **Infrastructure** | Kubernetes, Terraform, ArgoCD |

## Project Structure

```
siem-soar-project/
├── services/           # Go microservices
│   ├── gateway/        # API Gateway
│   ├── detection/      # Detection engine
│   ├── soar/           # SOAR orchestration
│   ├── ti/             # Threat intelligence
│   ├── query/          # Query engine
│   ├── case/           # Case management
│   ├── collector/      # Log collection
│   └── pipeline/       # Data pipeline
├── ai/                 # Python AI services
│   ├── models/         # ML models
│   │   ├── classifier/ # Alert classification
│   │   └── nl2sql/     # Natural language to SQL
│   ├── services/       # AI microservices
│   │   ├── triage/     # Alert triage
│   │   ├── copilot/    # Security copilot
│   │   └── agentic/    # Autonomous agents
│   └── common/         # Shared utilities
├── web/                # React frontend
├── pkg/                # Go shared packages
│   ├── config/         # Configuration
│   ├── logger/         # Logging
│   ├── errors/         # Error handling
│   ├── middleware/     # HTTP middleware
│   ├── repository/     # Data access
│   └── connector/      # External integrations
├── packages/           # TypeScript shared packages
├── infra/              # Infrastructure as code
│   ├── terraform/      # Terraform modules
│   ├── kubernetes/     # K8s manifests
│   └── docker/         # Docker configs
├── docs/               # Documentation
│   ├── adr/            # Architecture decisions
│   └── api/            # API documentation
└── scripts/            # Build & utility scripts
```

## Prerequisites

- **Go** >= 1.23
- **Python** >= 3.11
- **Node.js** >= 20.x
- **pnpm** >= 9.x
- **Docker** >= 24.x
- **Docker Compose** >= 2.x

## Quick Start

### 사용 흐름

  1. 신규 개발자 입사
          ↓
  2. DEVELOPMENT_SETUP.md 읽음 (이해)
          ↓
  3. 환경 구축 (Docker, Go, Python 설치)
          ↓
  4. make dev-up 실행 (Makefile 사용)
          ↓
  5. 이후 개발 중 계속 make 명령어 사용

### 1. Clone the repository

```bash
git clone https://github.com/your-org/siem-soar-project.git
cd siem-soar-project
```

### 2. Install dependencies

```bash
make install
```

### 3. Start development services

```bash
make dev-services  # Start databases, Kafka, etc.
```

### 4. Run services

```bash
# Run all services
make dev

# Or run individual services
cd services/gateway && go run .
cd ai && uv run python -m services.triage.main
```

## Development

### Building

```bash
make build          # Build all components
make go-build       # Build Go services only
make py-build       # Build Python packages only
make web-build      # Build web frontend only
```

### Testing

```bash
make test           # Run all tests
make go-test        # Run Go tests only
make py-test        # Run Python tests only
make web-test       # Run web tests only
```

### Linting

```bash
make lint           # Run all linters
make go-lint        # Run Go linter only
make py-lint        # Run Python linter only
make web-lint       # Run web linter only
```

### Pre-commit Hooks

```bash
make pre-commit     # Install pre-commit hooks
```

## Documentation

- [Architecture Decision Records](./docs/adr/)
- [API Documentation](./docs/api/)
- [Development Guide](./docs/guides/development-setup.md)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Proprietary - All rights reserved
