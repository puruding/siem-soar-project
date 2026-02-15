# ADR-0001: Monorepo Structure with Turborepo

## Status

Accepted

## Date

2024-01-15

## Context

The SIEM-SOAR platform consists of multiple services written in different
languages (Go, Python, TypeScript/React) and requires a unified development
and build workflow. We need to decide on the repository structure and
tooling for managing the codebase.

## Decision Drivers

- Multiple languages and frameworks (Go, Python, TypeScript)
- Shared dependencies and code between services
- Unified CI/CD pipeline
- Developer experience and onboarding
- Build performance and caching

## Considered Options

### Option 1: Polyrepo (Multiple Repositories)

Separate repository for each service and shared packages.

**Pros:**
- Clear ownership and boundaries
- Independent versioning
- Smaller clone sizes

**Cons:**
- Cross-repository changes are difficult
- Dependency management overhead
- Inconsistent tooling and standards
- Complex CI/CD orchestration

### Option 2: Monorepo with Nx

Single repository using Nx for build orchestration.

**Pros:**
- Mature tooling
- Good caching
- Affected-based testing

**Cons:**
- Primarily JavaScript/TypeScript focused
- Complex configuration for polyglot projects
- Larger learning curve

### Option 3: Monorepo with Turborepo + Language-specific Tools

Single repository using Turborepo for orchestration with native tools for
each language (Go modules, Python Poetry, pnpm).

**Pros:**
- Simple configuration
- Excellent caching (remote and local)
- Language-agnostic orchestration
- Native tooling for each language

**Cons:**
- Turborepo is JavaScript-centric
- Need additional tooling for Go/Python

## Decision

**Chosen option:** Option 3 - Monorepo with Turborepo

We will use a monorepo structure with:
- Turborepo for high-level build orchestration and caching
- Go modules with replace directives for shared packages
- Python Poetry for AI services
- pnpm workspaces for frontend packages

This provides the best balance of unified workflow and native tooling.

## Consequences

### Positive

- Single source of truth for all code
- Atomic changes across services
- Shared tooling configuration
- Efficient CI with affected-based builds

### Negative

- Larger repository size over time
- Need discipline in code organization
- Initial setup complexity

### Risks

- Build times may increase as codebase grows
  - Mitigation: Implement remote caching with Turborepo
- Conflicting dependency versions
  - Mitigation: Regular dependency updates, isolation between language runtimes

## Implementation

### Directory Structure

```
siem-soar-project/
├── services/        # Go microservices
├── ai/              # Python AI services
├── web/             # React frontend
├── pkg/             # Go shared packages
├── packages/        # TypeScript shared packages
├── infra/           # Infrastructure as code
├── docs/            # Documentation
└── scripts/         # Build and utility scripts
```

### Tasks

- [x] Initialize Turborepo configuration
- [x] Set up Go workspace with replace directives
- [x] Configure Python Poetry
- [x] Create root Makefile for orchestration
- [ ] Set up CI/CD pipeline
- [ ] Configure remote caching

## References

- [Turborepo Documentation](https://turbo.build/repo/docs)
- [Go Modules Reference](https://go.dev/ref/mod)
- [Poetry Documentation](https://python-poetry.org/docs/)
