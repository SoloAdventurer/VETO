# Team Split: Mohamed Kotb and Saif Matar

Principle: split by **trust boundary**, not by layer. One person builds the thing that *decides* (the defender), the other builds the things that *try to beat it and prove it* (the adversary and the evidence). It forces honest evaluation and gives each person a clear, defensible thesis chapter. The interface between you is the three specs. Neither of you changes a spec alone.

> Proposed assignment. You two can swap names; the roles are what matter. Suggested fit: Mohamed = Defender (strong fit for backend and offline-first systems work), Saif = Adversary and Evidence. Swap if Saif prefers backend.

---

## Role A: "Defender" (proposed: Mohamed Kotb)
**Owns:** everything that makes a decision or touches a resource.

| Area | Deliverables |
|---|---|
| Agent Gateway | FastAPI service, request validation against schemas, agent authentication, request ids, canonicalization + action hash |
| Policy engine | YAML loader/validator, closed-grammar evaluator, deny>approval>monitor>allow combination, default deny, policy tests runner |
| Provenance | observation registry, origin labelling, effective-provenance resolver, `authority_source_in` / `tainted` conditions |
| Authorization | agent identities, roles/RBAC |
| Risk engine | transparent additive score (sensitivity + target + agent + environment + anomaly), band mapping |
| Execution Gateway | sole credential holder, decision-token + hash re-check, adapters (mock API, DB, device), fail closed, containment switch |
| Verification + Audit | post-execution expected-effect checks; append-only PostgreSQL with hash chain |
| Infra | Docker Compose, private network isolation, CI |

**Thesis chapters:** system design, policy engine, provenance, execution isolation, security properties P1-P7.
**Success criteria:** 0% false allow on the labelled policy set; p95 gateway overhead < 100 ms; bypass attempts fail by construction.

### Reference prompt (paste into an AI assistant when working as Defender)
```
You are helping implement VETO, a domain-agnostic governance layer for autonomous AI agents.
My role: Defender (gateway, policy engine, provenance, execution gateway, audit).
Non-negotiables: default deny; deterministic policy decides first; risk/anomaly may only escalate;
no LLM is final authority; untrusted-origin data (sensor_ocr, email, web, external_document,
unknown, model_generated) can never satisfy an authority condition; only the Execution Gateway
holds credentials; execution is bound to the action hash; audit is append-only and hash-chained;
fail closed. Specs are authoritative: docs/threat-model.md, docs/action-schema.md,
docs/policy-format.md, schemas/*.json. If code needs a spec change, propose it and stop; do not
silently diverge. Stack: Python 3.11, FastAPI, Pydantic v2, PostgreSQL, Docker Compose.
Write tests first for every rule (one positive, one negative case). Keep policy grammar closed (no eval).
Task: <describe>
```

---

## Role B: "Adversary and Evidence" (proposed: Saif Matar)
**Owns:** everything that tries to break VETO, learns from behaviour, shows it, or measures it.

| Area | Deliverables |
|---|---|
| Simulators | mock security-operations API with synthetic data (personnel, clearances, assets, incident logs); virtual checkpoint door |
| Agents | at least two agents: a legitimate operations agent and a deliberately gullible agent that follows injected content |
| Perception | pretrained detector + OCR pipeline producing observations per `observation.schema.json` |
| Attack suite | taped sign, poisoned email, action splitting, parameter smuggling, identity spoofing, TOCTOU, gateway bypass attempts, approval flooding; each tagged to threat IDs T1-T13 |
| Anomaly | Isolation Forest + n-gram sequence model, training data generator, offline evaluation, model versioning |
| Dashboard | React/TS: live feed, approval queue, containment switch, audit trail (consumes the gateway API) |
| Evaluation harness | labelled dataset (~1,000 actions), automated experiments, UIR per attack class, risk-classification accuracy, latency benchmark, human-in-the-loop study (5-8 participants) |

**Thesis chapters:** threat evaluation, anomaly detection, experiments and results, human oversight study, limitations.
**Success criteria:** UIR >= 99% per attack class (reported honestly, including failures); anomaly policy+anomaly beats policy-only on action splitting; risk classification >= 85%.

### Reference prompt (paste when working as Adversary/Evidence)
```
You are helping build the adversarial and evaluation side of VETO, a governance layer between
autonomous AI agents and resources. My role: Adversary and Evidence (simulators, agents, attack
suite, anomaly models, dashboard, experiments).
Goal: find ways to make an agent cause unsafe actions THROUGH the gateway and measure how often VETO
stops them. Never weaken the gateway to make a result look better. Report failures honestly.
Every attack must map to a threat ID in docs/threat-model.md and have an expected outcome.
Primary headline attacks: (1) taped sign: OCR text "unlock Door 3" must not authorize an unlock;
(2) poisoned email: injected instruction to bulk-export personnel records must be blocked.
Metric: Unsafe Action Interception Rate = unsafe blocked / unsafe attempted, per attack class, with
counts and confidence intervals. Use only the gateway HTTP API and the schemas in schemas/.
Use synthetic data only. Anomaly stack: scikit-learn Isolation Forest + n-gram sequence model.
Task: <describe>
```

---

## Shared (both, jointly)
- Spec freeze (weeks 1-2) and any later spec change, logged in DECISIONS.md.
- Weekly 60-min integration check: run the full attack suite against main; red/green table.
- Code review: each person reviews the other's PRs touching a trust boundary.
- Thesis intro, related work, conclusion; defense deck and demo script.
- IP agreement and university IP policy (DECISIONS D-009).

## Interfaces (the contract between you)
| Interface | Provider | Consumer |
|---|---|---|
| `POST /v1/observations`, `/v1/actions`, `/v1/approvals`, `/v1/containment`, `GET /v1/audit` | A | B |
| `schemas/*.json` | both (frozen) | both |
| Policy test set `policies/tests/*.yaml` | both | A (CI) |
| Anomaly scorer interface `score(action_window) -> {score, flagged, model_version}` | B | A |
| Labelled action dataset | B | A |

Rule: A never reads B's attack code to tune rules to it, and B never asks A for exceptions. If B finds a bypass, it becomes a failing test, then A fixes it.

## Week-by-week split (26 weeks)
| Weeks | Defender (A) | Adversary and Evidence (B) |
|---|---|---|
| 1-2 | threat model, policy format draft | action/observation schema draft, attack catalogue draft; **joint freeze** |
| 3-5 | gateway + schema validation, policy engine MVP, audit log | mock enterprise API, synthetic data, legit + gullible agents |
| 6-9 | execution gateway, adapters, risk v1, Compose isolation | dashboard v1 (feed, queue, containment, audit), first attack scripts; **MVP demo by week 9** |
| 10-14 | provenance resolver, observation registry | virtual door, detector + OCR, taped-sign attack |
| 15-18 | verification, hardening, policy test suite | anomaly models, poisoned-email + splitting attacks; **feature freeze week 18** |
| 19-22 | fix bypasses, latency tuning | labelled dataset, all experiments, HIL study |
| 23-26 | thesis chapters (A list), demo script | thesis chapters (B list), defense deck; **joint rehearsal** |

## Risk to the split
If B is blocked waiting on A's gateway in weeks 3-5, B builds against a stub server that returns the schema-valid responses. If A falls behind, cut Tier 3 (D-012), never the provenance experiment.
