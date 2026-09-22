# ACDS → Real Product: Gap List, Constraints, and Where to Start

This ties together everything from the code audit, the market research, and the agentic-architecture doc into one thing: what's actually missing to call this a *product* (not a demo), and the decisions you need to lock in **before** writing code, because they change the database schema, the API shape, and the deployment topology if you get them wrong now and try to fix them later.

## First: decide which bar you're building to

These are genuinely different systems, not the same system at different levels of polish:

| | **Portfolio-grade** | **Real product-grade** |
|---|---|---|
| Users | You, demoing it | Multiple companies, each with their own users/data |
| Data isolation | One database, one admin | Tenant isolation — company A must never see company B's threats |
| Auth | JWT + roles (have this) | + org/workspace concept, invite flows, SSO eventually |
| Billing | None | Stripe/usage metering, plans |
| Compliance posture | "Here's my architecture and reasoning" | Actual controls mapped to a framework (SAMA CSF / ISO 27001), evidence, a DPA you can sign |
| Support | None | SLA, incident response process for *your* incidents |

If the near-term goal is job applications (as it was two conversations ago), **you don't need the right column.** A single-tenant, honestly-documented, live-and-working system is a complete and strong portfolio piece — most candidates show a repo with a broken deploy button; you'd have a live URL with real traces of an agent reasoning through a decision. Don't let "make it a real product" scope-creep you out of finishing the portfolio-grade version first.

If you're also seriously eyeing this as something to eventually offer through Kammand Security to GCC fintechs — plausible, given your actual client base — then multi-tenancy is a **day-one schema decision**, not a later refactor. Retrofitting tenant isolation into a system that was built single-tenant means touching every collection, every query, and re-auditing every access-control path. My recommendation: **add a `tenant_id` field to every collection and every query from the start**, even while you're the only tenant. It costs almost nothing now and is extremely expensive later.

---

## P0 — Blockers to calling this "deployable" at all

1. **Secrets & CORS** — already fixed in the patch from earlier; apply it before anything else goes live.
2. **No real destructive-action authorization model.** Right now `response_agent.py` executes quarantine/block/isolate based on a static JSON rule map with no per-action audit trail tying it to *why*. Before this touches anything real, every automated action needs: who/what triggered it, what evidence it cited, and a way to reverse it. This is also a prerequisite for the agentic loop's guardrails (previous doc).
3. **No backup/restore story.** MongoDB Atlas free tier has no automated backups. If this is going to hold real (even test) incident data, you need at minimum a scheduled `mongodump` to object storage before you'd call it "product-ready" — losing a demo tenant's data mid-interview-cycle is avoidable embarrassment.
4. **No rate limiting anywhere** — not on login (brute-force), not on the API generally, not on destructive actions (covered in the agentic doc as a specific adversarial scenario). `slowapi` or a reverse-proxy-level limiter (nginx/Caddy) is a half-day addition with outsized credibility payoff.
5. **CI doesn't gate anything** (`continue-on-error: true` everywhere). Fix incrementally: make lint blocking now (cheap, will pass), leave tests non-blocking until you've verified they actually pass in the CI environment (many need Mongo, which the current CI doesn't provision) — don't flip it all to strict and get a wall of red X's on a repo recruiters will look at.

## P1 — What separates "prototype" from "real system"

**Data & ML**
- Ship the ransomware and malware trained models (the notebooks already exist — this is training time + validation, not new engineering).
- Add model versioning: every prediction should record *which model version* made it. Right now there's no way to know if a detection came from v1 or a retrained v2.
- Replace the hardcoded `/system/health` and `/alerts` mock data with real `psutil` metrics and real alert generation — flagged before, still the single most embarrassing thing if someone opens dev tools on the live demo.
- Add a holdout/validation set check before any retrained model gets promoted — a real MLOps pattern (shadow evaluation), and directly relevant if you're positioning for AI/ML engineering roles.

**Agentic/AI layer**
- Everything in the previous roadmap doc — the tool-use loop, the guardrails, the eval set. This is the single highest-leverage technical addition for your specific job-search goal, so don't let the product-readiness list below dilute focus away from it.

**Ingestion**
- Decide explicitly: is live ingestion (real IMAP/Graph API mailbox, real Wazuh/Sysmon forwarding) in scope, or does this stay demo-data-driven with an honest label saying so? Both are legitimate — what's not legitimate is leaving it ambiguous so a reviewer assumes it's live when it's HuggingFace-dataset-driven.

**Security (beyond P0)**
- MFA for admin accounts — meaningful for a system that claims to protect banks, cheap to add (TOTP).
- Input validation/sanitization audit on every endpoint that accepts user-controlled content (email bodies, filenames) — this is also your first line of defense against the prompt-injection scenario once the LLM layer exists.
- Dependency scanning (Dependabot/`pip-audit`/`npm audit` in CI) — five minutes to enable, closes an entire class of "did you even check" interview questions.

**Observability**
- Structured logging is already a dependency (`structlog`) but doesn't look wired everywhere — audit that it's actually used consistently, not just imported.
- Basic uptime/error monitoring (Sentry free tier, UptimeRobot) — the difference between finding out your demo is down from a recruiter's email versus from a dashboard.

## P2 — Real product / SaaS layer (only if you're going the multi-tenant route)

- Org/workspace model with invite flows, not just individual user accounts.
- Billing (Stripe) and usage metering — especially important once LLM calls have real per-incident cost.
- A real onboarding flow (connect your mailbox, set your response policy) rather than admin-seeded demo data.
- Data residency consideration — if GCC banks are the actual target, where the database physically lives (Atlas region selection) becomes a real compliance question under frameworks like SAMA, not a hypothetical.
- Formal control mapping: pick ISO 27001 Annex A or SAMA CSF, map each control to what ACDS actually does (access control, logging, encryption, change management), and produce this as a document — genuinely valuable both as a sales artifact *and* as a portfolio piece that literally nobody else applying for AI-security roles will have, because it's exactly the crossover your GRC background gives you that a pure engineer doesn't.

---

## Constraints to lock in before you write more code

1. **Pick one ICP, not "banks in general."** "Phishing + credential-stuffing detection for GCC digital-first neobanks" is a pitch. "Autonomous cyber defense for financial institutions" competes with Darktrace and loses immediately on credibility. Narrow scope also directly simplifies the ingestion and compliance questions above.
2. **Set a hard LLM cost ceiling per incident before you build the agent loop**, not after. A runaway tool-call loop against Claude/GPT pricing is a real bill, not a hypothetical — the `max_steps` cap in the agentic doc is the code-level version of this constraint; the budget number is the business-level version. Decide it now (e.g., "$0.05/incident max") and design the loop to respect it.
3. **Single-tenant now, `tenant_id`-ready schema from day one** — per the table above. Don't build the org/billing UI yet; do make every document tenant-scoped.
4. **Don't connect this to a real, non-consenting mailbox or network.** If live ingestion is in scope, it's your own sandboxed test mailbox/test tenant, full stop — connecting it to anyone else's real traffic without an explicit agreement is both a legal and an ethical problem, independent of how good the detection is.
5. **Timebox the agentic rebuild to the phased plan already given** — one vertical slice (phishing) done properly beats four shallow ones. Resist the urge to parallelize across all threat types before Phase 1 is solid.
6. **Decide who reviews destructive-action design before it's live** — even solo, write down the approval-tier table from the agentic doc as an actual decision record (a short ADR/markdown file in `/docs`), not just something you remember. This is the artifact a technical interviewer will most want to see, and it costs an hour to write once you've already decided it.

## Suggested build order (combining this with the agentic roadmap)

1. Apply the security patch, fix rate limiting, deploy live (portfolio-grade, achievable this week).
2. Ship ransomware/malware model artifacts + fix the mocked health/alerts endpoints (closes the most visible gaps a reviewer will find).
3. Build the Phase 1 agentic slice (phishing tool-use loop + guardrails + adversarial eval set) — this is your headline differentiator.
4. Write the ADR for destructive-action approval tiers + a short control-mapping doc (ISO 27001 or SAMA CSF) — uniquely yours to produce, high leverage, low engineering cost.
5. Only then, if you're pursuing the product angle: tenant_id schema pass, org model, billing.

Steps 1-4 are genuinely achievable and give you a complete, honest, technically serious portfolio piece. Step 5 is a different project with a different timeline and business decisions (pricing, GTM) that are yours to make, not mine to spec.
