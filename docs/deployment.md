# Deployment Guide

SpindleX is designed for modern cloud environments where speed and minimal footprint are critical. Its "Zero-Dependency" architecture makes it ideal for Dockerized deployments.

## The "Zero-Dependency" Advantage

SpindleX is a pure-Python library. Unlike other SSH libraries, it does not require:

*   `gcc`
*   `python-dev` or `python3-dev`
*   System-level headers (`libssl-dev`, `libffi-dev`)

This results in **faster build times** and **smaller images**.

## Minimal Dockerfile

Here's how to create a production-ready Docker image with SpindleX:

```dockerfile
# Use a slim Python image
FROM python:3.11-slim-bookworm

# Create a non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Install SpindleX - No system dependencies needed!
# This step is extremely fast because it's just pure Python
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
