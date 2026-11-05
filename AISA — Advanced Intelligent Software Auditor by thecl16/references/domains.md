# The 16 audit domains

Use this as the checklist for the manual part of the audit. Scanners only produce leads; every domain below needs
Claude to **read the code** and decide. For each domain, record coverage in `narrative.json -> domain_coverage`
(`Reviewed`, `Partially reviewed`, `Not reviewed`, `Not applicable`) with notes on what was and was not examined.
"Reviewed, nothing found" and "not reviewed" are different statements and the report keeps them apart.

Finding IDs use the domain code: `AISA-SEC-001`.

---

## STR - Structure & Project Completeness
- Coherent layout; conventional directories; no orphaned or half-moved modules.
- Dependency manifest(s), lockfiles, `.gitignore`, README, license, env template present.
- Files referenced but missing (imports of non-existent modules, scripts in manifests pointing nowhere, Dockerfile COPY of absent paths).
- Leftover artifacts: committed `node_modules`, `__pycache__`, `.env`, build output, backups (`*.bak`, `copy of`).
- Empty files, placeholder directories, TODO/FIXME density.
- *Verify by*: listing the tree, cross-checking every manifest script/entrypoint against real files.

## ARC - Architecture & System Design
- Layering and boundaries (UI -> API -> service -> data); circular dependencies; god modules; business logic in controllers/views.
- Coupling to frameworks, hard-coded environment assumptions, global mutable state, singletons holding request data.
- Statelessness/scalability constraints (in-memory sessions, local-disk state, single-process assumptions, schedulers started per worker).
- Multi-tenancy / isolation model if applicable; configuration strategy; error-handling strategy; observability hooks.
- Consistency of patterns (three different ways to do the same thing = drift).
- *Verify by*: tracing one request end to end through every layer; drawing the dependency graph from imports.

## QUA - Code Quality
- Duplication (see `detect_duplicates.py`), long/complex functions, deep nesting, dead code, commented-out code.
- Naming, consistency, magic numbers/strings, type hints/typing discipline, lint/format configuration present and used.
- Error handling quality (swallowed exceptions, generic catches, error-as-return-value mixing).
- *Verify by*: reading the worst offenders flagged by scanners and judging whether they are real problems.

## LOG - Logic & Functionality
- Off-by-one, wrong operators, inverted conditions, unreachable branches, race conditions, unchecked `None`/`null`.
- Date/time, timezone, rounding and money handling (floats for currency), locale assumptions, integer overflow.
- State machines (order/payment/status transitions) that allow illegal transitions.
- Async/await misuse, missing `await`, unhandled promise rejections, shared mutable state across requests.
- *Verify by*: reasoning through edge cases (empty, zero, negative, huge, duplicate, concurrent); executing tests in the sandbox when possible.

## SEC - Security
- **Authentication**: password storage (bcrypt/argon2), session/JWT handling, token expiry, brute-force protection, MFA, default credentials.
- **Authorization**: every route checks identity AND ownership/role (IDOR), admin endpoints protected, multi-tenant filters on every query.
- **Injection**: SQL/NoSQL/command/template/LDAP/XPath; unsafe deserialization; SSRF; path traversal; XXE.
- **Client side**: XSS sinks, CSRF protection, CORS, cookie flags (HttpOnly, Secure, SameSite), CSP, open redirects.
- **Secrets & crypto**: hard-coded keys, weak algorithms, ECB, static IVs, `Math.random` for tokens, TLS verification off.
- **Input handling**: validation, file upload checks (type, size, path), rate limiting, mass assignment.
- **Supply chain**: unpinned/typo-squatted/unmaintained dependencies, install scripts, CI secrets exposure.
- Map findings to CWE/OWASP Top 10 where it adds clarity.
- *Verify by*: following untrusted input from source to sink in the code; for a claim of "exploitable", show the path with file:line at each hop.

## DAT - Database & Data Integrity
- Schema vs. code agreement (columns used but not defined, migrations missing/out of order), constraints (PK/FK/unique/not-null/check).
- Transactions around multi-step writes; idempotency; isolation level assumptions; deadlock-prone patterns.
- Indexes for queried columns; N+1 queries; unbounded `SELECT *`; pagination.
- Backups/retention, soft delete vs. hard delete, PII at rest, encryption of sensitive columns, row-level security (e.g. PostgreSQL RLS) correctness.
- Seed/mocked data leaking into real tables; default credentials in init scripts.

## API - API & Communication
- Route/contract consistency between clients and servers (use `scan/api_map.json`), HTTP method/status code correctness, versioning.
- Input/output validation and schemas; error response format; pagination; idempotency keys; rate limiting.
- CORS policy, auth on every route, webhook signature verification, timeouts/retries/circuit breakers on outbound calls.
- WebSocket/SSE lifecycle, message schema validation, backpressure.
- OpenAPI/Swagger accuracy versus real routes.

## UIX - Frontend & UI/UX
- Real data wiring (no hard-coded arrays posing as API results), loading/error/empty states, form validation (client AND server).
- Dead controls (empty handlers, `href="#"`), broken routes, unreachable screens, state management leaks.
- Accessibility basics (labels, alt text, focus, contrast), responsive layout, i18n/hard-coded strings.
- XSS-safe rendering, token storage (localStorage vs. httpOnly cookie), sensitive data in URLs/logs.
- Bundle hygiene: giant dependencies, unused code, source maps shipped.

## BIZ - Backend & Business Logic
- Does the code implement what the README/spec says? Compare each stated rule (pricing, limits, roles, workflows) with the actual code path.
- Calculation correctness (tax, discount, totals, rounding), authorization of business actions, workflow ordering, audit trails.
- Scheduled jobs/queues: retries, idempotency, poison messages, concurrency.
- Domain-specific compliance rules (e.g. financial reconciliation, payroll, grading) - check invariants explicitly.

## INT - External Integration & Dependencies
- Each third-party API/SDK: credentials handling, timeouts, retries, error mapping, webhook verification, sandbox vs. production endpoints.
- Dependency health: pinned, locked, deprecated/unmaintained, license compatibility, unused dependencies, undeclared (phantom) imports.
- Integrations that are *claimed* but stubbed (returns canned data, `if DEBUG: return fake`).
- If the network is available, run advisory scanners (see `tooling.md`) and record results; otherwise state "advisory lookup not performed".

## PRF - Performance & Optimization
- Algorithmic hot spots (nested loops over large data, repeated regex compile, string concatenation in loops), blocking I/O in async paths.
- Database: N+1, missing indexes, full-table scans, unbounded result sets; caching (absent, stale, unbounded); memory growth.
- Frontend: render churn, bundle size, unoptimised images, missing lazy loading.
- Resource management: unclosed files/connections, thread/process pool sizing.
- Do not claim "slow" without a reasoning or measurement; label estimates as such.

## TST - Testing & Reliability
- Presence, breadth and quality of tests: do they assert behaviour or just run code? Mocks hiding real integration? Flaky/sleep-based tests?
- Coverage of critical paths (auth, payments, data mutations); negative tests; test data realism.
- Run the suite in the sandbox: record pass/fail counts honestly, including failures that existed before any fix.
- Reliability: error handling, retries, timeouts, graceful degradation, health checks, logging quality, crash recovery.

## OPS - DevOps & Deployment
- Dockerfile quality (pinned base, non-root, multi-stage, no secrets in layers, `.dockerignore`), compose/k8s manifests, resource limits.
- CI/CD: runs tests/lint/build/security checks, protects main, caches, secrets handled via CI store.
- Config management: env vars, per-environment config, no debug in production, safe defaults, migrations on deploy.
- Observability: logs, metrics, tracing, alerts; backup and rollback story; infrastructure-as-code review.

## DOC - Documentation & Standards
- README accuracy (setup steps actually work? run them mentally or in the sandbox), API docs vs. code, architecture notes, env var documentation.
- Comments that lie (describe behaviour the code no longer has), stale TODOs, missing docstrings on public APIs.
- Contribution/coding standards, changelog, license present.

## CMP - Compliance & Privacy
- Personal data inventory (what PII is collected, where stored, how long), consent, minimisation, deletion/export capability.
- Logging of PII/secrets, encryption in transit/at rest, access controls on sensitive data, audit logs.
- Jurisdiction-sensitive rules *if evident from the project* (e.g. GDPR, Indonesian PDP Law/UU PDP, financial-sector regulations like OJK/BI requirements, PCI-DSS for card data). State clearly that this is a technical review, **not legal advice**, and mark regulatory conclusions `Potential`/`Unverified` unless the code proves the violation.
- Licence compliance of dependencies.

## SLP - Anti-Slop Audit
See `anti-slop.md`. This domain asks: *does the project actually do what it appears to do?*
Fake functionality, mock data in real paths, claims without implementation, hallucinated dependencies, AI leftovers,
copy-paste drift, and tests that cannot fail.
