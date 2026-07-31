FROM python:3.12-slim

LABEL maintainer="EP-Governance"
LABEL description="Governed PostgreSQL proxy for EP-Governance — runs on NAS"

WORKDIR /app

# Install system dependencies for psycopg and crypto
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY docker/proxy/requirements-proxy.txt .
RUN pip install --no-cache-dir -r requirements-proxy.txt

# Copy source code
COPY src/ /app/src/
COPY migrations/ /app/migrations/

# Set Python path
ENV PYTHONPATH=/app/src

# The proxy listens on port 8201 for token-based execution requests
EXPOSE 8201

# Run the proxy service
CMD ["python", "-m", "ep_governance.proxy_service"]