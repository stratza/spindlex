# Deployment Guide

SpindleX is designed for modern cloud environments where speed and minimal footprint are critical. Its lean architecture makes it ideal for Dockerized deployments.

## Lean Dependency Tree

SpindleX leverages the standard `cryptography` library for robust, secure cryptographic primitives. While it is not "zero-dependency," it carefully selects its dependencies to maintain a small footprint.

## Minimal Dockerfile

Here's how to create a production-ready Docker image with SpindleX:

```dockerfile
# Use a slim Python image
FROM python:3.11-slim-bookworm

# Install basic build dependencies for cryptography if binary wheels aren't available
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Install SpindleX
RUN pip install --no-cache-dir spindlex

# Copy your application code
COPY . .

# Run as non-root
USER appuser

CMD ["python", "main.py"]
```

## Security Hardening

When deploying SpindleX in production, consider these best practices:

1.  **Read-Only Root**: Run the container with a read-only root filesystem where possible.
2.  **Mount SSH Keys**: Never hardcode keys. Use Kubernetes Secrets or Docker Secrets and mount them into your container.
3.  **Strict Host Key Policy**: In production, avoid `AutoAddPolicy`. Instead, use `RejectPolicy` and provide a known hosts file.

```python
from spindlex.hostkeys.policy import RejectPolicy
from spindlex.hostkeys.storage import FileHostKeyStorage

client.set_missing_host_key_policy(RejectPolicy())
client.load_host_keys('/etc/ssh/known_hosts')
```

## Environment Variables

SpindleX respects several environment variables for configuration if used:

| Variable | Description |
| --- | --- |
| `SPINDLEX_LOG_LEVEL` | Set the default log level (INFO, DEBUG, etc.) |
| `SPINDLEX_BUFFER_SIZE` | Override the default window size for specialized networks |
