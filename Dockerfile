# syntax=docker/dockerfile:1
FROM dhi.io/python:3.14-debian13-dev@sha256:84c62df9f2a1fe35903c347a7c05fe8b62484baa49c40b1005f7b5c0c88b10f6 AS build-stage

# Copy and configure uv, to install dependencies
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /bin/
WORKDIR /app
# Install project dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --no-group dev --link-mode=copy --compile-bytecode --no-python-downloads --frozen

##################################################################################

FROM dhi.io/python:3.14 AS runtime-stage
LABEL org.opencontainers.image.authors=asi@dbca.wa.gov.au
LABEL org.opencontainers.image.source=https://github.com/dbca-wa/dependabot-reporter

# Copy over the project virtualenv
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"
COPY --from=build-stage /app /app
COPY *.py ./
