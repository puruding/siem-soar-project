# SIEM-SOAR Platform Documentation

## Overview

This directory contains all documentation for the SIEM-SOAR Integrated Platform.

## Structure

```
docs/
├── README.md           # This file
├── adr/                # Architecture Decision Records
│   ├── template.md     # ADR template
│   └── 0001-*.md       # Individual ADRs
├── api/                # API documentation
│   └── template.md     # API doc template
├── guides/             # User and developer guides
├── runbooks/           # Operational runbooks
└── diagrams/           # Architecture diagrams
```

## Documentation Types

### Architecture Decision Records (ADR)

Located in `/adr/`, these documents capture important architectural decisions
with their context and consequences. Use `template.md` when creating new ADRs.

**Naming convention:** `NNNN-short-title.md` (e.g., `0001-monorepo-structure.md`)

### API Documentation

Located in `/api/`, these documents describe the REST APIs for each service.
Use `template.md` when documenting new APIs.

### Guides

Located in `/guides/`, these provide step-by-step instructions for:
- Getting started
- Development setup
- Deployment procedures
- Feature usage

### Runbooks

Located in `/runbooks/`, these provide operational procedures for:
- Incident response
- System maintenance
- Troubleshooting
- Disaster recovery

### Diagrams

Located in `/diagrams/`, these contain:
- Architecture diagrams
- Sequence diagrams
- Data flow diagrams
- Network diagrams

## Contributing

1. Use the appropriate template for new documentation
2. Follow the existing naming conventions
3. Keep documentation up-to-date with code changes
4. Include diagrams where helpful
5. Review documentation changes in PRs

## Tools

- **Markdown:** All documentation is written in Markdown
- **Mermaid:** For diagrams that can be rendered in GitHub
- **Draw.io:** For complex architecture diagrams
- **OpenAPI:** For API specifications (generated from code)

## Quick Links

- [Getting Started Guide](./guides/getting-started.md)
- [Development Setup](./guides/development-setup.md)
- [API Reference](./api/)
- [Architecture Decisions](./adr/)
