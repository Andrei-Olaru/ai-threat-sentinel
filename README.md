# 🛡️ AI-Powered SIEM & Threat Sentinel

[![CI](https://github.com/Andrei-Olaru/ai-threat-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Andrei-Olaru/ai-threat-sentinel/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

An end-to-end **Security Information and Event Management (SIEM)** platform that combines **ML-based anomaly detection** (Isolation Forest) with **LLM-powered threat analysis** (Groq API) for automated root cause analysis, MITRE ATT&CK mapping, and remediation command generation.

> **🚧 Work in Progress** — This project is being built module by module. See the [Roadmap](#roadmap) below.

## Architecture Overview

```
Raw Logs → FastAPI Gateway → Redis Queue → Worker → ML Engine (Isolation Forest)
                                                   → Rule Engine (Sigma YAML)
                                                   ↓
                                              Groq LLM (RCA + MITRE ATT&CK)
                                                   ↓
                                              PostgreSQL → Dashboard (HTMX + SSE)
```

## Features

- **Real-time Log Ingestion** — Async FastAPI gateway with Pydantic v2 validation
- **ML Anomaly Detection** — Isolation Forest scoring on traffic feature vectors
- **AI-Powered Analysis** — LLM root cause analysis with MITRE ATT&CK mapping
- **Live Dashboard** — HTMX + Tailwind CSS with SSE alert feed and IP blocking
- **Production-Ready** — Structured logging, health probes, Docker, CI/CD pipeline
- **DevSecOps Pipeline** — GitHub Actions with linting, testing, and Docker build

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12, FastAPI (async), Pydantic v2 |
| **Queue** | Redis Streams (async decoupling) |
| **Database** | PostgreSQL + SQLAlchemy 2.0 + Alembic |
| **ML Engine** | scikit-learn (Isolation Forest) |
| **AI/LLM** | Groq API (llama-3.3-70b-versatile) |
| **Frontend** | HTMX + Tailwind CSS + SSE |
| **DevOps** | Docker, GitHub Actions, Prometheus metrics |
| **Deployment** | Render + Neon (PostgreSQL) + Upstash (Redis) |

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (for local infrastructure)
- [Groq API key](https://console.groq.com/keys) (free tier)

### Local Development

```bash
# Clone the repository
git clone https://github.com/Andrei-Olaru/ai-threat-sentinel.git
cd ai-threat-sentinel

# Create virtual environment and install dependencies
python -m venv .venv
.venv/Scripts/activate  # Windows
# source .venv/bin/activate  # macOS/Linux

pip install -e ".[dev]"

# Configure environment variables
cp .env.example .env
# Edit .env with your Groq API key

# Start infrastructure (PostgreSQL + Redis)
docker compose -f docker/docker-compose.yml up -d

# Run the application
python -m uvicorn sentinel.main:app --host 127.0.0.1 --port 8000 --reload

# Run tests
python -m pytest tests/ -v
```

### Using Makefile

```bash
make dev          # Install all dependencies
make run          # Start dev server
make test         # Run test suite
make lint         # Check code quality
make check        # Run lint + typecheck + tests
make docker-up    # Start Docker services
make docker-down  # Stop Docker services
```

## Project Structure

```
ai-threat-sentinel/
├── src/sentinel/           # Application source code
│   ├── api/                # FastAPI routes and middleware
│   ├── core/               # Config, logging, exceptions
│   ├── ingestion/          # Log simulator and Redis queue
│   ├── processing/         # Normalization and worker
│   ├── detection/          # ML engine and rule engine
│   ├── enrichment/         # Groq LLM client and prompts
│   ├── db/                 # SQLAlchemy models and repos
│   ├── dashboard/          # HTMX templates and SSE
│   └── metrics/            # Prometheus metrics
├── tests/                  # pytest test suite
├── docker/                 # Dockerfile and Compose
├── .github/workflows/      # CI/CD pipeline
└── docs/                   # Documentation
```

## Roadmap

- [x] **Module 1** — Architecture, project setup, FastAPI skeleton, CI pipeline
- [ ] **Module 2** — Log simulator, Redis ingestion queue
- [ ] **Module 3** — ML engine (Isolation Forest), rule engine
- [ ] **Module 4** — PostgreSQL persistence, Alembic migrations
- [ ] **Module 5** — Groq LLM integration (RCA, MITRE ATT&CK)
- [ ] **Module 6** — HTMX dashboard with live alert feed
- [ ] **Module 7** — Prometheus metrics and Grafana
- [ ] **Module 8** — Deployment (Render + Neon + Upstash)

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.