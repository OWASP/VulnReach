# Threat model

VulnReach is a reachability-aware SCA tool. It takes a repository, runs Trivy
over its dependencies, and then uses taint analysis, AST call graphs, route
extraction and (optionally) runtime coverage to decide which CVEs are actually
reachable. It ships as a FastAPI server with a dashboard (`api/`, `dashboard/`)
and a lifecycle CLI (`vulnreach/cli/`). `docs/threat-model.md` (STRIDE) and
`SECURITY.md` describe the same boundaries in more detail.

## What this project does and where untrusted input enters

The deployment we care about is a shared VulnReach server: several users with
their own accounts and API keys submit repositories to scan. Treat as untrusted:

- **HTTP API requests** from any authenticated or unauthenticated client:
  `POST /login`, `/api-keys*`, `POST /scan` (`repo_url`, `repo_path`,
  `config_path`, `tools`), and every `/scan/{scan_id}/...` and
  `/findings/{finding_id}/...` route in `api/server.py`. Users are untrusted
  with respect to each other; only `role == "admin"` may see other users' data.
- **The contents of a scanned repository.** A `repo_url` is cloned by
  `agents/agent_git.py`, and everything inside it is attacker-controlled:
  source files parsed by the reachability agents, manifests and lockfiles
  (`requirements.txt`, `package-lock.json`, `pom.xml`, Gradle files),
  OpenAPI specs, Dockerfiles/compose files, and an auto-discovered
  `vulnreach.yaml` config at the repo root.
- **Output of wrapped tools** (Trivy, Semgrep, tainter, schemathesis) and
  **LLM responses** (`intelligent_dast/llm_client.py`, `api/explain.py`,
  `api/next_steps.py`), since a malicious repo can steer what they emit.
- **Stored scan data** rendered back by the dashboard and the PDF export
  (`api/export.py`): repo names, file paths, package names and CVE text all
  originate from the scanned repo.

Trusted: the server operator, the server's own environment (`.env.local`,
`JWT_SECRET`), and a `config_path` that points at a file the operator placed
on disk.

## Components that matter most / least

Most important:
- `api/auth.py` and `api/server.py`: authentication, JWT/API-key handling,
  and the per-scan owner check (`_fetch_scan_owned`, which returns 404 for
  other users' scans). Any way to read, cancel, delete or export another user's scan, mint a
  key for another user, or reach a protected route without valid credentials.
- `agents/agent_git.py` and `core/orchestrator.py`: URL handling, clone
  target directory, and anything that lets a repo or request escape the scan
  work directory (path traversal via repo names, symlinks in the cloned tree,
  `repo_path`/`config_path` pointing outside intended locations).
- Static reachability parsers (`agents/reachability/`, `agents/agent_*_reachability.py`,
  `agents/agent_routextractor.py`, `correlation/`): crashes or code execution
  while *parsing* a malicious repo, and evidence spoofing that makes a
  reachable CVE be reported as unreachable (a false "safe" verdict is a
  security bug for this product).
- Storage (`storage/`): SQL injection, cross-user leakage.
- Dashboard/PDF output: stored XSS or injection from repo-controlled strings.

Less important but in scope:
- `intelligent_dast/` and `agents/agent_openapi_generator.py` (experimental):
  prompt injection from repo content that leads to actions beyond the scan's
  target, or to leaked secrets/API keys.
- The lifecycle CLI.

Out of scope:
- `labs/` (deliberately vulnerable sample apps) and `tests/fixtures/`.
- `libs/` (vendored tainter wheel) and the internals of Trivy, Semgrep,
  schemathesis and tainter: report those upstream.
- Vulnerabilities in the *target* applications VulnReach scans.

## Code execution of scanned repositories is by design (with limits)

Some agents run the scanned project's code on purpose:
- `agents/agent_pytest_coverage.py` runs the repo's own test suite.
- `agents/agent_dynamic_reachability.py` builds and runs the repo's
  Dockerfile/compose project, only when `VULNREACH_ALLOW_DOCKER_DAEMON=true`
  is set by the operator, and through `docker-socket-proxy` in the runtime
  compose profile. eBPF mode needs a separate opt-in.

Arbitrary code execution *by the target's own tests or containers* inside those
paths is documented behaviour, not a finding. What is a finding:
- Code execution from a repo **when those tools are not selected** or when
  the Docker opt-in is off (e.g. during cloning, config loading, or static
  parsing; `vulnreach.yaml` in the repo enabling runtime or tools the
  requester did not ask for).
- Escaping the socket proxy restrictions to control the host daemon.
- Injection into the argv of `git`, `trivy`, `semgrep`, `pytest` or `docker`
  via repo URLs, file names, or config values (e.g. option injection through
  a `repo_url` starting with `-`).

## How to exercise it

- Unit and integration tests: `pytest tests/ -q` from `/src`. The eBPF and
  Java-in-Docker tests need a Docker daemon and are not usable in the audit VM.
- Start the server: `JWT_SECRET=... uvicorn main:app --port 8000`, then
  `POST /login` and drive the API with curl. `USAGE.md` and `docs/api.md`
  document the request shapes.
- Scan a local target without network: `POST /scan` with
  `repo_path` set to one of `labs/python_vuln_app`, `labs/pygoat`,
  `labs/multitier_vuln_app` and a config path. Trivy's DBs are pre-fetched in
  the image and `TRIVY_SKIP_DB_UPDATE` keeps it offline.
- `semgrep --config auto` needs network and will fail offline; that is
  expected in this environment.

## How you rate severity

- **Critical:** unauthenticated access to scans/keys, auth bypass, or code
  execution on the VulnReach host from a submitted repo or API request
  without the runtime opt-in.
- **High:** cross-user data access or modification by an authenticated
  non-admin; host compromise via the Docker socket proxy when runtime is
  enabled; path traversal that reads/writes outside the work directory;
  SQL injection.
- **Medium:** stored XSS in the dashboard or PDF export; a malicious repo
  forcing a CVE that is reachable to be reported as unreachable; leaking
  `JWT_SECRET`, LLM API keys or other server secrets via prompt injection or
  error messages.
- **Low:** information disclosure of non-secret metadata, missing hardening
  with no concrete exploit.
- DoS/resource exhaustion via oversized repos or requests is low unless small
  input causes disproportionate cost (quantify input size and time).

## Anything to leave alone

- Default/example credentials and secrets in `.env.example`, compose files,
  `labs/` and test fixtures.
- Vulnerabilities in `labs/` apps; they are intentionally vulnerable.
- Code execution by a target's tests or containers inside
  `pytest_coverage` / `dynamic_reachability` when the operator selected them
  (see above).
- Missing features already listed as gaps in `docs/threat-model.md` (MFA/SSO,
  signed audit logs, artifact attestation, per-user scan quotas) unless you
  show a concrete exploit.

## Reports

Include the affected file and line, a request sequence or minimal malicious
repo that reproduces the issue, and a patch if you have one. Patches should
come with a test in `tests/`.
