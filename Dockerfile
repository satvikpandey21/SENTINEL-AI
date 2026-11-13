# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE=python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d
FROM ${PYTHON_IMAGE} AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY requirements.txt ./
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --require-hashes -r requirements.txt
COPY packages/sentinel-security packages/sentinel-security
COPY apps/admin-api apps/admin-api
COPY apps/demo-api apps/demo-api
COPY apps/event-worker apps/event-worker
RUN pip wheel --no-deps --wheel-dir /wheels ./packages/sentinel-security ./apps/admin-api ./apps/demo-api ./apps/event-worker \
    && pip install --no-index --no-deps /wheels/*.whl

FROM ${PYTHON_IMAGE} AS runtime
ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 sentinel && useradd --uid 10001 --gid sentinel --no-create-home sentinel
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY alembic.ini ./
COPY migrations ./migrations
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "sentinel_api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--no-access-log", "--log-config", "/app/uvicorn-log.json"]
COPY uvicorn-log.json ./

FROM runtime AS test
USER root
COPY requirements-dev.txt ./
RUN --mount=type=cache,target=/root/.cache/pip pip install --require-hashes -r requirements-dev.txt
COPY tests ./tests
COPY scripts ./scripts
COPY pyproject.toml ./
USER 10001:10001
CMD ["python", "-m", "pytest", "-p", "no:cacheprovider", "-m", "integration", "-q"]
