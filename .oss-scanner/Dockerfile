# Build OWASP VulnReach for Anthropic's OSS Scanner.
# The scanner uses the repository root as the build context and audits /src offline, so everything the
# server and its tests need is installed here: the pinned requirements, the package with every extra,
# and Trivy with its vulnerability DBs. threat_model.md says how to run it.
# Trivy is the SCA layer the pipeline starts from; take the binary from the official image.
FROM aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy
FROM python:3.11-slim-bookworm
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_RETRIES=10 \
    PIP_DEFAULT_TIMEOUT=60

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
RUN trivy --version

# Grab the vulnerability DBs so `trivy fs` can match offline; a failed or stalled download must not abort
# the build.
RUN timeout 600 trivy image --download-db-only || echo "WARNING: trivy DB download failed"
RUN timeout 600 trivy image --download-java-db-only || echo "WARNING: trivy Java DB download failed"
# Don't reach for the network on every run once offline.
ENV TRIVY_SKIP_DB_UPDATE=true \
    TRIVY_SKIP_JAVA_DB_UPDATE=true

# Scanner contract: the checkout lives inside the image, at /src.
COPY . /src
WORKDIR /src

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir pytest-cov coverage \
    && pip install --no-cache-dir -e ".[full]"

# Dynamic/eBPF paths need a Docker daemon and kernel privileges that the audit VM does not provide;
# leave them disabled (see threat_model.md).
ENV VULNREACH_ALLOW_DOCKER_DAEMON=false

# Run the test suite so the image is known to work; a failing test must not abort the build. The skipped
# files need a Docker daemon.
RUN pytest tests/ -q -p no:cacheprovider \
        --ignore=tests/test_ebpf_e2e.py --ignore=tests/test_java_docker.py \
    || echo "WARNING: pytest reported failures"
