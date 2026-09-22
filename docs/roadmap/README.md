# ACDS Roadmap — Read This First

This folder is the shared context for anyone (or any coding agent) picking up work on ACDS. Read `00` (this file) then the doc matching whatever phase you've been assigned before touching code.

- `01-agentic-architecture.md` — why the current "agents" are a fixed pipeline, not real agents; the target tool-use loop; the guardrail design (confidence tiers, prompt-injection defense).
- `02-product-readiness-brief.md` — the full gap list (P0/P1/P2), the portfolio-vs-real-product fork, and the constraints to respect.
- `03-file-assignments.md` — which files belong to which phase/workstream, and the sequencing between them.

## Ground rules for ANY change made under this roadmap

**This is enhancement work. Nothing here should change existing behavior that already works.**

1. **Additive, not refactoring.** New files, new functions, new optional parameters, new endpoints — yes. Rewriting or restructuring an existing function's signature, an existing endpoint's response shape, or the existing detection/response pipeline flow — no, unless the specific task explicitly says so.
2. **Don't remove the fallback logic.** `malware_service.py`, `ransomware_service.py`, and `pe_service.py` all have rule-based fallback scoring for when no trained model is loaded. That stays, even after real models are shipped — it's the graceful-degradation path, not dead code.
3. **Don't change `main.py`'s router wiring or existing route paths/methods.** The frontend and the `test_cases/` suite depend on the current API shape. Add new routers/endpoints; don't rename or move existing ones.
4. **Don't touch files outside your assigned phase.** If a task seems to require changing a file that isn't listed for your phase in `03-file-assignments.md`, stop and flag it rather than editing it — that's a sign the phase boundary needs adjusting, not a green light to expand scope.
5. **Preserve the demo account / rate-limiting / real health-metrics behavior already shipped** in `backend/api/routes/auth.py`, `backend/api/routes/dashboard.py`, and `backend/core/rate_limit.py` — these are already-completed work, not something to "improve" as part of a new phase.
6. **When in doubt about whether something counts as a "change" vs an "enhancement," it's a change** — ask before doing it.
