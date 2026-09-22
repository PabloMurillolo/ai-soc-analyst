# v0.1 validation record

Validated on macOS ARM64 / Python 3.13.2, September 21, 2026.

## Completed

- `python -m pytest -q`: **16 passed**. Two upstream dependency deprecation warnings remain; no failed tests.
- `node --check app/static/app.js`: passed.
- `pip check`: no broken requirements.
- `docker compose config --quiet`: passed configuration validation.
- Native one-command startup: application seeded successfully and served on 127.0.0.1:8000.
- Browser: dashboard populated from the API, incident evidence displayed, offline false-positive answer referenced the event, analyst status/note saved with an audit entry, and the saved state survived reload.
- Browser: benign simulation added two events and zero incidents. Search empty state and severity filtering exercised.
- Responsive inspection: narrow layout rendered and desktop document width matched the 1440px viewport without document overflow. The incident table scrolls horizontally on small screens.
- Secrets and runtime artifacts excluded from the published source allowlist.

## Not verified

- Docker image build/start: Docker CLI exists, but the local Docker daemon is not running. Configuration validation is not a successful container runtime test.
- Live Ollama generation: Ollama is not installed in this environment. The offline path is exercised; AI failure behavior is covered in tests.
- Python 3.11 and GitHub Actions execution: configured in CI, not part of the native Mac test result.
- Enterprise telemetry, production scalability, measured detection precision/recall, and adversarial model robustness are outside this synthetic v0.1 scope.
