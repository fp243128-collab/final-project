# SentinelX — Agent Rules

These are binding rules for any AI agent (Antigravity or otherwise) working on this codebase.
They apply on every generation, every file, every session — not just the first one. Read this
file before touching any code, and re-read it if you're picking the project back up after a gap.

`design_model.md` is the product/design spec. This file is the **design_model.md AND AGENT_RULES.md**: how the agent
is required to work while building it. Treat both as binding. If they ever conflict, ask —
don't silently pick one.

The standard here is a senior engineer with 30+ years shipping production software: careful,
unhurried, allergic to shortcuts, and unwilling to hand over anything they haven't verified.
Fast-but-wrong is not a valid tradeoff on this project.

---

## 0. Code quality must match "Production-Ready" spec

This project is explicitly building an enterprise-grade SaaS product for multi-tenant SOC2-compliant
security operations — not a university project or internal MVP. Every component, hook, type,
and backend service must meet the standards described in [design_model.md:55-57](#55-production-grade-standards) and [design_model.md:61](#61-testing-and-code-quality).

If you would not ship this code to a customer who expects 99.9% uptime and SOC2 auditability,
you are not done.
so make it hundred 100% complete and perfect. if you dont know about something
ask me but dont just guess it
also make responsive for all devices (mobile, tablet, desktop, ultrawide)

- **Performance**: Every page must feel instant. Use Next js optimization, virtualization for large lists, and avoid unnecessary re-renders. The UI must remain responsive even when rendering hundreds of findings.
- **Type Safety**: Types are not optional. Every API response, Redux state, form value, and component prop must be fully typed. If an interface is missing, generate it. If there is a choice between a string and a well-typed enum, choose the enum.
- **Accessibility (A11y)**: Every interactive element must have keyboard navigation, focus states, and ARIA labels where needed. Do not rely on users having a mouse.
- **Error Handling**: Do not swallow errors to keep a demo "pretty." Use the robust error boundaries and toast notifications described in [design_model.md:57.4](#574-security-and-error-handling). Unhandled exceptions are a defect, not a feature.
- **Security**: No hardcoded secrets, no ignoring auth checks, no any types in security-sensitive code. See rule #6.

## 1. No fabricated data, ever

- Never invent numbers, statistics, scores, or results and present them as if they came from
  real computation. A risk score, an accuracy metric, a scan count — every number on screen must
  trace back to either real logic (the formula in `design_model.md` §12) or clearly-labeled seed
  data (`design_model.md` §63).
- Once backend integration starts, `Math.random()` / hardcoded arrays standing in for real data
  are a defect, not a placeholder — flag them explicitly in code comments as `// TODO: replace
  with real <endpoint>` rather than letting them look finished.
- Never claim a test passed, a build succeeded, or a scan completed without actually running it.
  If something wasn't run, say so.

## 2. No shortcuts on correctness

- Don't silently narrow scope to make something easier. If a requested feature is ambiguous or
  larger than it looks, say so and propose the smallest correct version — don't quietly build a
  fake or partial version and present it as complete.
- Don't catch and swallow errors to make a demo look clean. Every `catch` block either handles
  the error meaningfully or surfaces it — never an empty catch, never a silent `pass`.
- Don't skip input validation, auth checks, or RBAC checks "for now." Security architecture
  (`design_model.md` §31) is not a phase-2 item — every endpoint is built with auth from the
  first commit, even against mock data.
- Don't copy-paste a working component and forget to change what needs to change (IDs, keys,
  labels). Review the diff before calling something done.

## 3. Explain before generating anything large

- Before generating a new page, service, or schema, briefly state: what you're about to build,
  which section of `design_model.md` it implements, and any assumption you're making that isn't
  explicitly in the spec. One or two sentences — not a wall of text, but never silent.
- If a request conflicts with something already built (a route that already exists, a schema
  field already defined), say so and ask which should change, rather than creating a second,
  inconsistent version.

## 4. Build incrementally, verify each step

- Follow the generation order in `design_model.md` §57. Do not jump ahead to backend
  integration while the UI shell is still unfinished, and do not touch six pages in one
  generation when one was asked for.
- After generating a feature, state what was and wasn't tested. "Built and unit-tested the risk
  formula; UI wiring not yet tested" is an honest status. "Done" with no caveats, when there are
  caveats, is not acceptable.
- Every non-trivial piece of logic (risk scoring, CSPM rule evaluation, RBAC checks) gets a test
  per `design_model.md` §62 in the same generation it's written in — not deferred to "later."

## 5. Consistency is non-negotiable

- One name for the product: **SentinelX**. One design system: the colors, type, and spacing in
  `design_model.md` §4. Don't introduce a new color, font, or component pattern without checking
  §4/§47 first.
- Match existing naming conventions exactly (route names, DB table names, component names) —
  check `design_model.md` §27/§28/§48–50 before inventing a new one.
- If you must deviate from the spec (a library doesn't support something, a pattern doesn't
  scale), say exactly what you're deviating from and why, in plain terms — not buried in code
  comments no one will read.

## 6. Security discipline (applies to every generation, not just §31)

- Never put secrets, API keys, or long-lived cloud credentials in frontend code, committed files,
  or logs — this includes example/demo credentials that look real.
- Least privilege by default: every new cloud integration, service account, or DB role gets the
  minimum permissions the feature needs, never broader "to save time."
- Treat every user input as untrusted: validate on the backend even if the frontend also
  validates. Frontend validation is UX, not security.

## 7. When something is genuinely uncertain

- If a requirement in `design_model.md` is ambiguous, pick the most conservative, most secure
  interpretation, state the assumption in one line, and proceed — don't block on it unless the
  ambiguity is safety- or auth-critical, in which case ask.
- If you don't know whether something will work (a library version, an API's real behavior),
  say so rather than presenting a guess as fact.

## 8. Definition of "done" for any single piece of work

A feature is not done until:

```
✓ It implements exactly what its design_model.md section describes (no less, no more)
✓ It has the tests §62 requires for that category of logic
✓ It has real auth/RBAC checks, not stubbed-out ones
✓ No fabricated data is presented as real
✓ Errors are handled visibly, not swallowed
✓ Naming and styling match the existing codebase
✓ The agent has stated, in plain language, what was built and what wasn't tested
```

If any of these isn't true, the honest status is "in progress," not "done."

---

**Bottom line:** move carefully, verify what you claim, never fake a result to make progress
look faster than it is. A senior engineer's reputation is built on the code that doesn't break
six months later — build like someone is going to review this line by line.
