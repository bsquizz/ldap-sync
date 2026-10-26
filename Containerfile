# Multi-stage build: deps are installed in a UBI builder (has pip), then copied into the
# distroless Red Hat Hardened Image (Project Hummingbird) runtime, which has no shell or
# package manager and runs as non-root UID 65532.
#
# Dependencies are installed with `pip --target` and run via `python -m` so nothing depends
# on console-script shebangs or the interpreter path. Both stages are Python 3.12 so wheels
# (e.g. PyYAML's) are ABI-compatible.
#
# NOTE: confirm the runtime image tag and that `python` resolves on PATH against the catalog
# (https://catalog.redhat.com, `hi/` namespace). Pin by digest for reproducible builds.

FROM registry.access.redhat.com/ubi9/python-312 AS builder
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir --target=/app .

FROM registry.access.redhat.com/hi/python:3.12
WORKDIR /app
COPY --from=builder /app /app
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 65532
ENTRYPOINT ["python", "-m", "ldap_sync"]
CMD ["--config", "/etc/sync/config.yaml"]
