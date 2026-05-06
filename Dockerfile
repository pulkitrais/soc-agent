FROM python:3.11-slim

LABEL maintainer="Sentinel Investigator"
LABEL description="SOC investigation platform for Microsoft Sentinel"

# Security: run as non-root
RUN groupadd -r socapp && useradd -r -g socapp socapp

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY .streamlit/ ./.streamlit/

# Create data directories with correct ownership
RUN mkdir -p data/sessions data/exports data/query_library \
    && chown -R socapp:socapp /app

USER socapp

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app/main.py", \
    "--server.port=8501", \
    "--server.address=0.0.0.0", \
    "--server.headless=true", \
    "--browser.gatherUsageStats=false"]
