# syntax=docker/dockerfile:1
FROM dhi.io/python:3.13-debian13-dev@sha256:afbe9dc3a5482aa5a10a1b3f6b169d71cfb0565d6ca223279af3c60696ae1cbe AS build-stage

# Copy and configure uv, to install dependencies
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /bin/
WORKDIR /app
# Install project dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --no-group dev --link-mode=copy --compile-bytecode --no-python-downloads --frozen

##################################################################################

FROM dhi.io/python:3.13 AS runtime-stage
LABEL org.opencontainers.image.authors=asi@dbca.wa.gov.au
LABEL org.opencontainers.image.source=https://github.com/dbca-wa/dependabot-reporter

# Copy over the project virtualenv
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"
COPY --from=build-stage /app /app
COPY *.py ./
