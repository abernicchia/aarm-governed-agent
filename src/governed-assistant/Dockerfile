# Build context must be the repository root (see azure.yaml docker.context).
FROM python:3.13-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v1.4.2/opa_linux_amd64_static \
    && chmod +x /usr/local/bin/opa \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY policies /app/policies
COPY policy-engine/policy/lib/*.rego /app/policies/rego/
COPY src/governed-assistant/requirements.txt /app/src/governed-assistant/requirements.txt
RUN pip install --no-cache-dir -r /app/src/governed-assistant/requirements.txt

COPY src/governed-assistant /app/src/governed-assistant

WORKDIR /app/src/governed-assistant

ENV GOVERNANCE_MANIFEST=/app/policies/manifest.yaml \
    PYTHONUNBUFFERED=1

EXPOSE 8088

CMD ["python", "main.py"]
