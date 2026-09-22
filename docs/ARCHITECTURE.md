# Architecture and trust boundaries

FastAPI owns the lifecycle and serves static assets from an explicit directory. Startup creates an SQLite schema and seeds demo scenarios only when no simulation runs exist. Environment variables are loaded from an optional ignored `.env` file.

## Data model

- `runs`: simulation ID, scenario name, creation timestamp.
- `events`: unique event ID, run foreign key, timestamp, JSON record.
- `incidents`: run and rule references, title, severity, status, host, user, and matched evidence JSON. A uniqueness constraint prevents duplicate same-rule/same-entity incidents within a run.
- `audit`: ordered detection and analyst-decision entries linked to an incident.

Writes use transactions; simulations commit events and incidents together. Connections enable foreign keys. WAL and a 15-second busy timeout support the small concurrent local workload. Schema creation is idempotent; there is no migration framework yet.

Timestamps are timezone-aware UTC ISO 8601; the browser renders them in local time. Each new simulation receives new run/event IDs and deliberately produces a new independent incident when the rule matches. Authentication detection retains the first threshold-crossing window; remaining records still exist in the events table.

## Trust boundaries

The browser talks to its same-origin API. Cross-origin writes are rejected; hostnames are restricted to localhost, 127.0.0.1, and the test host. This is not authentication. Local programs and users with database access are trusted by this single-user design.

The detector only consumes generated fixtures. No event field is executed. Documentation IP ranges and `.example` destinations avoid referring to real targets. Templates and LLM output have no tool permissions. Ollama requests use a fixed loopback URL, finite timeout, bounded questions, and an evidence-only system prompt. Prompt instructions are a mitigation, not a guarantee against hallucination or injection.

The dashboard uses a restrictive content security policy and escapes interpolated data. FastAPI's interactive documentation uses its own limited CDN/script policy; application routes retain the stricter policy. Model error bodies and internal exceptions are not returned to the browser.

## Design tradeoffs

The dependency-free frontend reduces setup and supply-chain complexity. SQLite matches the single-user local scope. Explicit deterministic rules make behavior explainable; they are not a replacement for mature detection content. Offline mode makes the demo reproducible without claiming generative intelligence. Local inference is optional and hardware/model dependent.
