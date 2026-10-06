# EntrAudit vs. ScubaGear — Comparison & Roadmap

## What ScubaGear is

[ScubaGear](https://github.com/cisagov/ScubaGear) is CISA's (Cybersecurity and Infrastructure Security Agency) open-source tool for assessing an M365 tenant against the government's published **Secure Configuration Baselines** — part of the broader SCuBA (Secure Cloud Business Applications) project, and the engine behind **BOD 25-01** compliance submissions for federal agencies. It's PowerShell-based, free, and covers the same problem space we do (M365/Entra config assessment), which makes it a fair and useful comparison point — but it is a **continuous compliance tool for federal agencies**, not a pentest-engagement tool, and that difference shapes almost every design decision below. It's also far more mature: multi-year, federally-funded, with dedicated test tenants and nightly CI runs. Worth being honest about that rather than pretending we're peers.

## Side-by-side

| | **EntrAudit** | **ScubaGear** |
|---|---|---|
| Architecture | Single-language: PowerShell collects *and* evaluates | Split: PowerShell collects, **Open Policy Agent/Rego** evaluates |
| Scope | 64 checks / 10 categories (incl. Forms, Defender, Intune/Autopilot — not in ScubaGear) | ~113 policies / 7 products (incl. Power Platform — not in ours) |
| Policy numbering | `ENTRA-01`, `EXO-01`, etc. | `MS.AAD.3.1v1` (product.section.policy + version) |
| Rating model | **Severity** (Critical→Informational), pentest-style | **Criticality** (SHALL/SHOULD/MAY, RFC 2119), compliance-style — no severity at all |
| Per-finding content | Title, Summary, Evidence, Remediation, AdminCenterPath | Rationale, NIST 800-53 mapping, MITRE ATT&CK mapping |
| Auth | Interactive, per-service UPN, optional split across accounts | Interactive **or** cert+service-principal (unattended), GCC/GCC High/DoD env support |
| Exception handling | None | YAML: Exclusions, Annotations, Omissions (see below) |
| Manual-check status | `ManualReview` — first-class status | `Manual` — first-class status (same idea) |
| Output | Excel (branded cover+dashboard+tabs), CSV, JSON, HTML | HTML, JSON, CSV (no Excel) |
| Testing | **None against a live tenant** — simulated data only | Pester unit tests + Rego unit tests + Selenium functional tests against real test tenants, nightly CI |
| Update/versioning | None | `SCUBAGEAR_SKIP_VERSION_CHECK`, PSGallery releases, per-policy `v1`/`v2` suffixes |

## Where EntrAudit's differences are deliberate, not gaps

Don't "fix" these by copying ScubaGear:

- **Severity ratings, not SHALL/SHOULD/MAY.** A pentest report needs to tell a client what to fix first. Compliance criticality doesn't map to exploitability or blast radius — a SHALL requirement and a SHOULD requirement can carry very different real-world risk. Keep severity.
- **Narrative Summary/Evidence/Remediation per finding**, not a NIST/MITRE citation. Pentest report writers lift this text close to verbatim into a client deliverable. A control-framework citation is useful *context*, not useful *prose* — see the proposal below for a middle ground.
- **Single-run, single-tenant, human-in-the-loop.** We're not trying to be a scheduled compliance monitor. The CLI's filtering/sorting already optimizes for "run once, write a report, move on" — not "run nightly forever."

## Proposed changes, prioritized

### 1. Exception/waiver mechanism with mandatory justification — **High value, Medium effort**
ScubaGear's `OmitPolicy` (requires `Rationale`, optional `Expiration`) and `AnnotatePolicy` (requires `Comment` on failures) are directly useful for us, reframed for pentest language: a client often says "we accept this risk, here's why" mid-engagement, and right now EntrAudit has no way to record that — you'd just... not mention the finding, losing the audit trail of *why*.

**Proposal:** a `-WaiverFile` param on `EntrAudit.Core.ps1` pointing to a small YAML/JSON file: `CheckId`, `Justification` (required), `AcceptedBy`, `Expiration` (optional). Waived findings still run and still appear in the report, but with `Status = Waived` (new enum value, distinct from `Pass`/`Fail`/`ManualReview`), shown gray like ScubaGear's Omitted, with the justification text in the Evidence column. Touches: `New-M365CheckResult.ps1` (add `Waived` to the ValidateSet), `Invoke-EntrAudit.ps1` (apply waivers post-run), `Write-EntrAuditExcelReport.ps1` (new conditional-formatting color), `EntrAudit.Core.ps1` (new param + help text).

### 2. Live-tenant validation harness — **High value, Large effort, do this before anything else**
This is the single biggest gap, and it's one we already flagged ourselves multiple times this build (every Graph property name is unverified against reality). ScubaGear's answer is expensive (dedicated test tenants, Pester, nightly CI) — we don't need that scale, but we need *something*.

**Proposal, cheapest version that's still real:** don't build Selenium/CI infrastructure. Instead, get ~20 minutes against one real test tenant (even a free M365 dev tenant) running `-ListChecks` then a full `-All` pass, and fix whatever breaks. That alone would outweigh a lot of other roadmap work. If a reusable test tenant becomes available, a lightweight Pester suite that asserts "each check returns a well-formed result object without throwing" (not full compliant/non-compliant fixtures like ScubaGear — too much for 64 checks) is a reasonable middle ground.

### 3. Cert-based service-principal auth for unattended runs — **Medium value, Medium effort**
Useful if RootSec ever re-runs EntrAudit against the same client periodically, or wants a scheduled/CI-triggered run rather than a human typing UPNs each time. Not urgent for one-off pentest engagements (our actual primary use case), but cheap to add alongside the existing interactive model rather than replacing it.

**Proposal:** add `-AppId`/`-CertificateThumbprint`/`-TenantId` as an alternate connection mode on `Connect-EntrAudit.ps1`, used instead of (not in addition to) the UPN params when present. `Connect-MgGraph` already supports cert auth natively; EXO/SPO/Teams connection cmdlets have app-only equivalents too. Document the Entra app registration + required Graph application permissions (mirrors ScubaGear's non-interactive setup docs) in the README.

### 4. GCC/GCC High/DoD environment awareness — **Low-Medium value, Small effort**
If RootSec ever tests a US government or defense client, every `Connect-*` call needs different endpoints (`-Environment USGov` etc. on `Connect-MgGraph`, different EXO/SPO URIs). Currently EntrAudit has zero awareness of this and would likely just fail confusingly against a GCC tenant.

**Proposal:** a `-M365Environment` param (`Commercial` default, `GCC`/`GCCHigh`/`DoD`) threaded into `Connect-EntrAudit.ps1`'s connection calls. Small and self-contained; only build when it's actually needed for an engagement.

### 5. Optional NIST 800-53 / MITRE ATT&CK tags per check — **Low value for us, Small effort, nice-to-have**
Some clients (especially regulated industries) want findings traced to a framework. ScubaGear hand-maintains this per policy, which is a lot of ongoing curation for a 64-check tool.

**Proposal:** add an optional `Framework` field to `New-M365CheckResult` (e.g. `@{ 'NIST' = 'IA-2(1)'; 'MITRE' = 'T1556' }`) populated only where we're already confident (several of our checks map cleanly — phishing-resistant MFA is NIST IA-2(1)/MITRE T1556 same as ScubaGear's). Don't backfill all 64 at once; add opportunistically. Low priority — nice polish, not something a client is likely to ask for in a pentest deliverable the way they would in a compliance submission.

## Ideas considered and rejected

- **OPA/Rego split** — wrong tool for our scale. ScubaGear's split earns its complexity across 113 policies maintained by a large team over years; for 64 checks maintained by us, a second language/runtime dependency (OPA binary, Rego test suite) is pure overhead with no compensating benefit. PowerShell functions are already readable and directly testable.
- **YAML config file as the primary interface** — we already have a CLI with `-Category`/`-Severity`/`-Status` filtering that covers the "customize what runs" need. A full config-file *language* (ScubaGear's is ~200 lines of options) is solving a multi-run, multi-tenant, long-term-maintenance problem we don't have.
- **GUI config app** (`Start-ScubaConfigApp`) — not warranted for a tool one or two people run per engagement. Pure maintenance cost.
- **"First run with no config to baseline, second run with config to compare"** two-pass workflow — makes sense for a compliance tool re-run monthly against a slowly-drifting tenant. Doesn't fit a single pentest engagement's timeline.
- **Full Selenium/nightly-CI functional test suite** — right instinct (we need *some* real-tenant validation), wrong scale. See proposal #2 for the right-sized version.

## Bottom line

Adopt #1 (waivers) and #2 (real-tenant validation) — both genuinely strengthen EntrAudit as a pentest tool and neither requires buying into ScubaGear's compliance-tool architecture. Treat #3/#4 as "build when an engagement actually needs it," not speculative work. #5 is cheap polish, lowest priority. Everything in "rejected" stays rejected unless EntrAudit's actual use case changes (e.g. if it ever needs to run unattended across many tenants on a schedule, revisit Rego and config-file questions from scratch — don't retrofit).
