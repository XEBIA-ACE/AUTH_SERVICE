# ---------------------------------------------------------------
# Auth Service — Multi-stage Dockerfile
#
# Stage 1 (builder): install dependencies into an isolated layer
# Stage 2 (runtime): copy only what's needed for a minimal image
# ---------------------------------------------------------------

# ── Stage 1: Builder ────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install system build deps (for psycopg2, bcrypt compilation)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python deps into a prefix directory
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: Runtime ────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Create a non-root user for security
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# Install only runtime system libraries (no compiler)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from the builder stage
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Health check — liveness probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/v1/health')" || exit 1

# Default command: Gunicorn with 4 workers
# Override via docker run ... gunicorn --workers N ...
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "4", \
     "--worker-class", "sync", \
     "--timeout", "30", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "wsgi:application"]
