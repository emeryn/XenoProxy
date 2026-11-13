FROM python:3.13-alpine3.22 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Alpine links against musl, for which an upstream project may ship no wheel.
# The toolchain is here so such a dependency builds from source; it stays in
# this stage and never reaches the runtime image.
RUN apk add --no-cache \
      build-base \
      libffi-dev \
      openssl-dev \
      postgresql-dev \
      cargo

WORKDIR /build
COPY pyproject.toml ./
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install .

# The audit gate fails the build, it does not warn. It runs against the resolved
# third-party set, since this project itself is not published to an index.
RUN /opt/venv/bin/pip install pip-audit==2.10.1 \
 && /opt/venv/bin/pip freeze --exclude xenoproxy-backend --exclude pip-audit > /tmp/audit-set.txt \
 && /opt/venv/bin/pip-audit --strict --progress-spinner off -r /tmp/audit-set.txt \
 && /opt/venv/bin/pip uninstall -y pip-audit \
 && rm -f /tmp/audit-set.txt

# Compiled artefacts and test suites of the dependencies are dead weight at
# runtime, and the C sources left by a source build are the largest part of it.
RUN find /opt/venv -name "*.pyc" -delete \
 && find /opt/venv -name "__pycache__" -type d -prune -exec rm -rf {} + \
 && find /opt/venv -name "tests" -type d -prune -exec rm -rf {} + \
 && find /opt/venv -name "*.c" -delete \
 && find /opt/venv -name "*.h" -delete \
 && find /opt/venv -name "*.pyx" -delete


# The suite runs against the same resolved dependency set as production, with
# the development extras on top. Declared here rather than assembled in the
# CI file so that running the tests locally and running them on a runner are
# the same command.
FROM builder AS test

COPY pyproject.toml ./
RUN /opt/venv/bin/pip install ".[dev]"

ENV PATH="/opt/venv/bin:$PATH"     PYTHONPATH=/src     PYTHONDONTWRITEBYTECODE=1
WORKDIR /src


FROM python:3.13-alpine3.22 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app \
    HOME=/tmp

# libseccomp backs the in-process filter that denies process creation;
# libpq is what asyncpg needs at runtime. Nothing else is added, and the
# package manager's index is not kept.
RUN apk add --no-cache libseccomp libpq \
 && addgroup -g 10001 -S xenoproxy \
 && adduser -u 10001 -G xenoproxy -S -H -s /sbin/nologin xenoproxy

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=10001:10001 alembic.ini ./
COPY --chown=10001:10001 migrations ./migrations
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 entrypoint.py ./entrypoint.py

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"]

ENTRYPOINT ["python", "/app/entrypoint.py"]
CMD ["api"]
