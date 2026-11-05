# Anti-Slop Audit

**Slop** is work that *looks* finished but is not: the code, UI, docs or tests suggest a capability that the system
does not actually have. It is common in AI-assisted and rushed projects and is the main reason "it has the file"
must never be accepted as "it works".

The goal of this domain is to separate **present** from **real**.

## Taxonomy (what to hunt for)

| Class | Typical signs | How to confirm |
|---|---|---|
| **Fake functionality** | function named `process_payment`/`send_email`/`encrypt` that returns a constant or `pass`; `if True:` branches; success responses with no work behind them | Read the body and every caller; check whether any side effect (DB write, HTTP call, file) exists |
| **Mock data leakage** | arrays named `mock_*`, `sampleUsers`, faker/mock libs imported outside tests, lorem ipsum, `john.doe@example.com` in app code | Trace the variable to where it is returned/rendered; check for a real data source behind it |
| **Simulated async** | `setTimeout`/`Future.delayed` wrapped in a Promise that resolves a literal | Check whether any network/storage call happens; check callers |
| **Dead UI** | empty `onClick`, `onPressed: null`, `href="#"`, buttons without handlers, forms posting nowhere | Find the handler; follow to API; confirm a route exists |
| **Broken wiring** | client calls `/api/orders`, server defines `/api/order`; env var read but never defined; config keys unused | `scan/api_map.json`, grep for every env var/config key |
| **Misleading claims** | README says "fully tested", "AI-powered", "real-time", "CI/CD", "secure", "production-ready" | `scan/claims.json` plus manual probe: is there a test suite? an ML/LLM call? a websocket server? a pipeline file? |
| **Hallucinated dependencies** | imports of packages absent from the manifest; names that look plausible but do not exist on the registry; mismatched import/package names | `PHANTOM-DEP-*` leads; if the network is available verify the package exists on the registry |
| **Hallucinated APIs** | calls to functions/methods/CLI flags that the library does not have | Check against the installed library source or docs; run in sandbox |
| **AI/paste residue** | `# ... rest of code`, `// existing implementation`, "As an AI language model", `YOUR_API_KEY_HERE`, duplicated near-identical files | `SLOP-ELISION` leads; read surrounding code for missing logic |
| **Test theatre** | tests with no assertions, `assert True`, tests that only mock the unit under test, snapshot of an error page, skipped everything | Read the tests; run them; mutate the code mentally (would any test fail?) |
| **Placeholder docs** | template README, boilerplate comments restating the code, docs for features that do not exist | Compare docs to code |
| **Copy-paste drift** | near-duplicate modules with small divergences; one copy fixed, one not | `DUP-BLOCK` leads; diff the copies |
| **Commented-out code & shortcut notes** | large commented blocks, "for now", "in a real app" | Decide whether the shortcut is on a live path |

## Procedure

1. Start from scanner leads (`SLP` domain, `scan/claims.json`, `scan/antislop.json`).
2. For **every claim** in README/docs/UI copy, write a row in the Feature Verification Matrix (`features.json`):
   claimed in -> implemented in -> how verified -> result.
3. For each suspicious function, **read it and its call sites**. Decide: real, partial, stubbed, or faked.
4. Execute where possible (sandbox): start the smallest piece that proves the feature (call the function, hit the route with a test client, run the test).
   If you cannot execute, the best result is `Appears Working (not executed)` - never `Verified Working`.
5. Record findings with severity by *impact of the deception*: a fake payment/auth is Critical/High; a lorem-ipsum paragraph is Low/Medium.
6. Report slop neutrally and factually. Describe what the code does, not who wrote it or how.

## Rules of evidence

- A regex hit is a **lead** (`Potential`). Promote to `Confirmed` only after reading the code (`manual-code-read` with notes) or executing it.
- "No evidence found" is **not** "does not exist": say what you searched (files, patterns, libraries) and mark `Unverified` or `Potential` if the search could have missed it (dynamic loading, generated code, other repos).
- A stub in an abstract base class, interface, protocol, test double or documented extension point is **not** slop. Dismiss with `Not Applicable` and a reason.
- Claims that are merely aspirational ("we aim to be scalable") are Informational at most.

## Severity guide for slop

| Situation | Severity |
|---|---|
| Fake or constant-returning authentication/authorization/payment/encryption/validation on a live path | Critical / High |
| Core feature advertised but absent or simulated (data never persisted, "AI" is `random.choice`) | High |
| Mock data returned by a real endpoint or shown as real in the UI | Medium / High |
| Documentation claims not backed by code (tests, CI, scalability, AI) | Medium / Low |
| Hallucinated/undeclared dependency that breaks clean installs | Medium / High |
| Dead buttons, placeholder text, commented-out code, stale TODOs | Low |
