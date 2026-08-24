# =============================================================================
# Multi-stage Dockerfile for AI Threat Sentinel
#
# Why multi-stage?
# Stage 1 (builder): installs all dependencies into a virtual env
# Stage 2 (runtime): copies only the venv + source code — no pip, no gcc
# Result: ~150MB image instead of ~800MB (smaller = faster deploys, less attack surface)
# =============================================================================

# --- Stage 1: Builder ---
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies for compiled packages (asyncpg, hiredis)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Create virtualenv inside the build stage
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only dependency files first (Docker layer caching optimization)
# If dependencies don't change, Docker reuses this cached layer
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy source code (changes more often — this layer rebuilds more frequently)
COPY src/ ./src/

# --- Stage 2: Runtime ---
FROM python:3.12-slim AS runtime

# Security: run as non-root user
RUN groupadd --gid 1001 sentinel && \
    useradd --uid 1001 --gid sentinel --shell /bin/bash --create-home sentinel

WORKDIR /app

# Install only runtime system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 curl && \
    rm -rf /var/lib/apt/lists/*

# Copy virtualenv from builder (the only thing we need)
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./

# Switch to non-root user
USER sentinel

# Health check — Docker/Render can monitor container health
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/healthz || exit 1

EXPOSE 8000

# Start with uvicorn (production settings)
CMD ["uvicorn", "sentinel.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--log-level", "info"]
