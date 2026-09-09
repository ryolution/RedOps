FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REDOPS_DATABASE_URL=sqlite:////data/redops.db \
    REDOPS_AUDIT_PATH=/data/audit.jsonl

WORKDIR /app
COPY pyproject.toml README.md ./
COPY requirements/linux-py3.13-runtime.txt /tmp/runtime.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/runtime.txt
COPY redops ./redops
RUN pip install --no-cache-dir --no-deps --no-build-isolation . \
    && useradd --uid 10001 --create-home redops \
    && mkdir /data /reports \
    && chown redops:redops /data /reports
COPY labs ./labs
USER 10001:10001
ENTRYPOINT ["redops"]
CMD ["--help"]

FROM runtime AS inventory
USER root
RUN apt-get update && apt-get install --no-install-recommends -y nmap \
    && rm -rf /var/lib/apt/lists/*
USER 10001:10001

FROM runtime AS default
