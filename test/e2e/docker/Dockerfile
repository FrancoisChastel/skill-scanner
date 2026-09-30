# End-to-end test image: the package installed as a user would, next to the real coding agents and
# external analyzers, in a container that cannot touch the host. Built by scripts/e2e-docker.sh.
FROM node:22-bookworm

ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl jq python3 python3-venv ca-certificates unzip procps \
 && rm -rf /var/lib/apt/lists/*

# Optional external analyzers. A failed install only turns their checks into skips.
RUN arch=$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64) \
 && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${arch}.tar.gz" | tar -xz -C /usr/local/bin gitleaks || true
RUN arch=$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo amd64) \
 && curl -fsSL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_${arch}" \
 && chmod +x /usr/local/bin/osv-scanner || true
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# The coding agents, at their latest versions, so setup and the adapters meet real installs.
RUN npm install -g @anthropic-ai/claude-code @openai/codex opencode-ai @earendil-works/pi-coding-agent skills@1 typescript@5 \
 && npm cache clean --force

RUN useradd -m -s /bin/bash tester
USER tester
WORKDIR /home/tester
ENV PATH="/home/tester/.local/bin:/home/tester/.npm-global/bin:${PATH}" \
    NPM_CONFIG_PREFIX=/home/tester/.npm-global \
    DISABLE_TELEMETRY=1 DO_NOT_TRACK=1 NO_COLOR=1

RUN uv tool install cisco-ai-skill-scanner || true
RUN uv tool install "git+https://github.com/NVIDIA/skillspector.git" || true
RUN uv tool install semgrep || true

# The package under test: a tarball in pkg/ (pre-release) or the given version from npm (post-release).
ARG SKILL_SCANNER_VERSION
COPY --chown=tester:tester pkg/ /home/tester/pkg/
RUN tarball=$(ls /home/tester/pkg/*.tgz 2>/dev/null | head -1); \
    if [ -n "$tarball" ]; then spec="$tarball"; else spec="@french-castle/skill-scanner@${SKILL_SCANNER_VERSION}"; fi; \
    echo "$spec" > /home/tester/pkg/SPEC && npm install -g "$spec"
ENV SKILL_SCANNER_VERSION=${SKILL_SCANNER_VERSION}

COPY --chown=tester:tester run.sh fixtures.py mock-jev.mjs adapters.mjs /home/tester/tests/
CMD ["bash", "/home/tester/tests/run.sh"]
