# Lightweight Python 3.12 Slim base
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy dependency configuration
COPY backend/pyproject.toml backend/uv.lock* ./backend/

# Synchronize backend dependencies
WORKDIR /app/backend
RUN uv sync --frozen --no-install-project || uv sync --no-install-project

# Copy ONLY backend application source code
COPY backend/src /app/backend/src

# Copy ONLY ML models and inference source (EXCLUDING 14GB+ ml/data)
COPY ml/src /app/ml/src
COPY ml/models /app/ml/models

# Expose backend API and WebSocket port
EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV KAFKA_BOOTSTRAP_SERVERS=kafka:29092
ENV KAFKA_TOPIC=network_flows
ENV WINDOW_SECONDS=15
ENV ALERT_THRESHOLD=40.0


# Start FastAPI server
CMD ["uv", "run", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
