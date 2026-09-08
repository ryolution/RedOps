FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REDOPS_DATABASE_URL=sqlite:////data/redops.db \
    REDOPS_AUDIT_PATH=/data/audit.jsonl

WORKDIR /app
COPY pyproject.toml README.md ./
COPY redops ./redops
RUN pip install --no-cache-dir '.[postgres]' \
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
