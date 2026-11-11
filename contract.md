# Policy contract — Freshness-aware Authorization (rule SYS-0002-R01)

> **Policy version: 5.0.2.** Version history is at the end, under **Changelog**.
>
> **Specialised PDP.** This project decides record access based on an **already resolved** action authorization, unit match, assignment freshness and approved exceptions. It runs **behind a trusted PEP/backend** that builds the entire input (identity from IAM, already resolved permissions, assignment from the records system, exception from an authorised store, and server time). **The end client never builds the input.** The policy does not authenticate, does not manage identities or roles, does not compute permissions, does not query databases and does not administer exceptions: it only checks consistency and applicability over trusted data.

## INPUT (what the enforcement point sends to OPA)

The **input root must be a JSON object**; `null`, a string, an array or a number is rejected as `DENY_INVALID_INPUT`.

```json
{
  "actor": {
    "id": "u-001",
    "unit": "UNIT_A",
    "allowed_actions": ["read", "update"]
  },
  "action": "read",
  "resource": {
    "record_id": "rec-123",
    "assigned_unit": "UNIT_A",
    "assignment_status": "FRESH",
    "assignment_timestamp": "2026-06-28T10:00:00Z",
    "assignment_max_age_seconds": 3600
  },
  "exception": {
    "id": "exc-777",
    "actor_id": "u-001",
    "record_id": "rec-123",
    "authorised_actions": ["read"],
    "valid_from": "2026-06-28T00:00:00Z",
    "valid_until": "2026-06-29T00:00:00Z",
    "source_status": "FRESH",
    "source_timestamp": "2026-06-28T10:00:00Z",
    "source_max_age_seconds": 3600,
    "approved_by": "approver-x"
  },
  "now": "2026-06-28T10:15:00Z"
}
```

(`exception` is `null` when there is no active exception; the example shows it populated in order to document its fields.)

Fields:

| Field | Type | Required | Notes |
|---|---|---|---|
| `actor.id` | non-empty string | yes | unique identifier of the actor |
| `actor.unit` | non-empty string | yes | organisational unit of the actor, per IAM |
| `actor.allowed_actions` | non-empty array of strings | yes | actions already authorised by the corporate system (trusted data from the PEP). The policy does **not** compute roles or permissions: it only checks membership |
| `action` | non-empty string | yes | requested action; it **must be in `actor.allowed_actions`** to be grantable. If an exception is used, it must also be in `exception.authorised_actions` |
| `resource.record_id` | non-empty string | yes | record identifier |
| `resource.assigned_unit` | non-empty string | yes (if `assignment_status` is `FRESH`/`STALE`) | unit the record is assigned to |
| `resource.assignment_status` | enum: `FRESH`, `STALE`, `UNAVAILABLE` | yes | freshness state of the data, computed by the adapter before reaching here |
| `resource.assignment_timestamp` | RFC 3339 string | yes (if `FRESH`/`STALE`) | when the assignment data was produced; parsed with `time.parse_rfc3339_ns` |
| `resource.assignment_max_age_seconds` | number ≥ 0 | yes | threshold used by the adapter to decide FRESH vs STALE. **Rego uses it to detect contradictions** (see *Design note*), not to recompute the state |
| `exception` | object or `null` | yes | **the key must always be present**; use `null` when there is no active exception (a missing key makes the input invalid) |
| `exception.id` | non-empty string | if `exception != null` | unique identifier of the exception; echoed in the output as `applied_exception_id` when applied |
| `exception.actor_id` | non-empty string | if `exception != null` | who the exception benefits |
| `exception.record_id` | non-empty string | if `exception != null` | which record it covers |
| `exception.authorised_actions` | array of strings | if `exception != null` | which actions it covers; **non-empty strings only**. `action` must be included |
| `exception.valid_from` | RFC 3339 string | if `exception != null` | start of the validity window; parsed with `time.parse_rfc3339_ns` |
| `exception.valid_until` | RFC 3339 string | if `exception != null` | end of the validity window; `valid_from <= valid_until` is enforced |
| `exception.source_status` | enum: `FRESH`, `STALE`, `UNAVAILABLE` | if `exception != null` | freshness of the exception record itself, independent of the assignment. **An exception only grants access if its `source_status == "FRESH"`** |
| `exception.source_timestamp` | RFC 3339 string | if `source_status` is `FRESH`/`STALE` | when the exception record was read; Rego checks `source_status` against this age |
| `exception.source_max_age_seconds` | number ≥ 0 | if `source_status` is `FRESH`/`STALE` | freshness threshold of the exception source |
| `exception.approved_by` | non-empty string | if `exception != null` | traceability of who approved it |
| `now` | RFC 3339 string (year 1678–2261 inclusive) | yes | evaluation instant, injected by the enforcement point; parsed with `time.parse_rfc3339_ns` |

**Design note (responsibilities and consistency):**

- **Computing the state (`FRESH`/`STALE`/`UNAVAILABLE`) lives in the adapter, outside Rego.** The policy decides *what to do* given a state, not *how to compute* the state. The assignment and the exception are evaluated **independently**: they are two distinct sources that can fall out of sync.
- **Exception freshness: modelled, not assumed.** The exception carries its own `source_timestamp` and `source_max_age_seconds`, and Rego validates that `source_status` does not contradict that age (same criterion as the assignment). Modelling the freshness of the exception source was preferred over declaring it inside the trust base, so that an exception declared `FRESH` over an expired record is rejected as invalid input instead of granting access.
- **Rego does NOT recompute freshness, but it DOES detect contradictions.** It is an explicit design choice that Rego cross-checks the declared `assignment_status` against the computed age `now − assignment_timestamp` versus `assignment_max_age_seconds`. Convention: `age ≤ max_age ⇒ FRESH`; `age > max_age ⇒ STALE`. If the declared state contradicts that relation (for example `status = FRESH` but `age > max_age`), the input is considered **invalid** and `DENY_INVALID_INPUT` is returned. Rego does not overwrite the adapter's state: it rejects it when incoherent.
- **Temporal comparison by instant, not by string.** All instants are converted to nanoseconds with `time.parse_rfc3339_ns` before being compared. This makes the comparison correct even when `now` and the exception window arrive with **different time offsets** (for example `Z` vs `+02:00`), which a lexical string comparison would get wrong.

**Temporal rules (normative summary):**

- Comparison uses the **actual instant with nanosecond precision**; never lexical comparison.
- `now` **comes from the backend/server**; the client does not supply it.
- A **future** `timestamp` (`> now`) is **invalid** (`DENY_INVALID_INPUT`).
- There is **no implicit or configurable clock tolerance** in this version.
- Convention: `age ≤ max_age ⇒ FRESH`; `age > max_age ⇒ STALE`.
- With **`max_age_seconds = 0`**, only an age **exactly equal to zero** (`now == timestamp`) counts as `FRESH`; any positive age declared `FRESH` is incoherent → invalid.
- **Leap seconds `:60`** are **not** accepted by this contract, even though other readings of RFC 3339 may accept them.
- **Year range actually accepted by the implementation: `1678..2261` inclusive** (limit of `time.parse_rfc3339_ns` as `int64` nanoseconds). Outside it → invalid.
- **Dates validated by calendar before parsing.** The RFC 3339 shape is checked with a regex and, in addition, the real calendar is validated (month range, day according to month and leap year, hour, minute, second and offset). Only an instant that passes all of this reaches `time.parse_rfc3339_ns`. This way a date with a valid shape but an impossible value (for example `2026-02-31`) is rejected as invalid input and the policy **does not abort, not even under `--strict-builtin-errors`**.
- **Representability, not just validity.** A date can have a correct shape and calendar and still not be representable by OPA as `int64` nanoseconds (the useful range of `time.parse_rfc3339_ns` covers roughly that span). That is why the year is limited to **`1678..2261` inclusive** **before** parsing, and the parse is additionally required to **actually return a number** before it is used. Out-of-range dates (for example years `0000` or `9999`) → `DENY_INVALID_INPUT`, with `result` always defined.

## OUTPUT (what OPA returns)

The policy **always** returns a structured, complete `result` object (query `data.freshauthz.records.result`), even for invalid or incomplete input. `decision`, `reason_code` and `execution_allowed` are emitted **together, from a single `outcome` object**, so they cannot fall out of sync with each other.

```json
{
  "decision": "ALLOW",
  "reason_code": "ALLOW_UNIT_MATCH",
  "execution_allowed": true,
  "rule": "SYS-0002-R01",
  "actor_id": "u-001",
  "record_id": "rec-123",
  "assignment_status": "FRESH",
  "applied_exception_id": null,
  "unused_exception_present": false,
  "validation_errors": [],
  "evaluated_at": "2026-06-28T10:15:00Z",
  "policy_version": "5.0.2"
}
```

| Field | Type | Notes |
|---|---|---|
| `decision` | enum: `ALLOW`, `ALLOW_WITH_EXCEPTION`, `ESCALATE`, `DENY` | the final decision |
| `reason_code` | string (closed, stable enum) | fixed code: `DENY_INVALID_INPUT`, `DENY_ACTION_NOT_ALLOWED`, `DENY_SOURCE_UNAVAILABLE`, `ALLOW_UNIT_MATCH`, `ALLOW_EXCEPTION_APPLIED`, `DENY_UNIT_MISMATCH`, `ESCALATE_STALE_ASSIGNMENT` |
| `execution_allowed` | boolean | `true` only for `ALLOW` and `ALLOW_WITH_EXCEPTION`; `false` for `DENY`, `ESCALATE` and invalid input |
| `rule` | string | fixed identifier of the evaluated rule |
| `actor_id` / `record_id` | string \| null | audit echo **sanitised by type**: string if the input carries it as a string, `null` otherwise |
| `assignment_status` | string \| null | the freshness state used; one of `FRESH`/`STALE`/`UNAVAILABLE`, or `null` if absent or mistyped |
| `applied_exception_id` | string \| null | `exception.id` of the exception actually applied; only in `ALLOW_WITH_EXCEPTION`, `null` otherwise |
| `unused_exception_present` | boolean | `true` only when the decision was `ALLOW` by direct match **and** a basic applicable exception also existed for that same actor/record/action. An audit signal |
| `validation_errors` | array of strings | **ordered** list of input problems; empty (`[]`) when the input is valid. Non-empty ⇔ `reason_code == "DENY_INVALID_INPUT"` |
| `evaluated_at` | string \| null | echo of `input.now` **sanitised by type**: string or `null` |
| `policy_version` | string (semver) | policy version |

### Input validation → `DENY_INVALID_INPUT`

Before the business logic, the policy validates the input. If `validation_errors` is not empty, `outcome` is:

```json
{ "decision": "DENY", "reason_code": "DENY_INVALID_INPUT", "execution_allowed": false }
```

It is marked invalid when, among others:

- Any of `actor.id`, `actor.unit`, `action`, `resource.record_id` is missing or not a string.
- `assignment_status` is absent or outside the enum.
- `assignment_max_age_seconds` is not a number **or is negative** (`< 0`).
- `now` is not valid RFC 3339.
- With `FRESH`/`STALE`: `assigned_unit` is missing, or `assignment_timestamp` is missing/not RFC 3339, **or `assignment_timestamp` is in the future (`> now`)** — future data cannot be FRESH.
- The `exception` key **does not exist** (it is required even when its value is `null`); or it is present and is neither an object nor `null`; or, being an object, some field is missing or broken (`id`, `actor_id`, `record_id`, `authorised_actions`, `valid_from`, `valid_until`, `source_status`, `approved_by`).
- With `exception.source_status` `FRESH`/`STALE`: `source_timestamp` is missing (or is not RFC 3339, or is in the future), or `source_max_age_seconds` is missing (or is negative), **or `source_status` contradicts its real age** (same criterion as the assignment).
- The input **root** is not a JSON object (it is `null`, a string, an array or a number).
- Some required string field is **empty**: `actor.id`, `actor.unit`, `action`, `resource.record_id`, `resource.assigned_unit`, or the exception's ids / `approved_by`.
- A date with valid shape and calendar **is not representable** by OPA (year outside 1678–2261, for example `0000` or `9999`), or the parse does not produce a number.
- Some date has RFC 3339 shape but is **impossible in the calendar** (month/day/hour/offset out of range, for example `2026-02-31`).
- The exception has `valid_from` **later than** `valid_until`, or `authorised_actions` contains an element that is not a string or is an empty string.
- The assignment state **contradicts** its timestamp/`max_age` (see *Design note*).

### Decision logic (declarative: mutually exclusive rules)

Rego evaluates a set of rules; for any **valid** `input`, exactly one `outcome` branch is satisfied. The conditions are mutually exclusive by construction.

Helper rules (pure functions of `input`):

- `input_valid` ⇔ `validation_errors` is empty.
- `action_allowed` ⇔ `action ∈ actor.allowed_actions` (trusted list already resolved by the corporate system; the policy only checks membership).
- `source_available` ⇔ `resource.assignment_status != "UNAVAILABLE"`.
- `unit_matches` ⇔ `resource.assignment_status == "FRESH"` and `actor.unit == resource.assigned_unit`.
- `exception_basically_applicable` ⇔ an `exception` exists, matches on `actor_id`, `record_id`, `action ∈ authorised_actions`, and `now` falls within the window `[valid_from, valid_until]` (nanosecond comparison, both bounds **inclusive**).
- `exception_valid` ⇔ `exception_basically_applicable` **and** `exception.source_status == "FRESH"`. An exception is only valid if it is itself `FRESH`, whether the assignment is `FRESH` or `STALE`.
- `exception_applicable_and_valid` ⇔ `resource.assignment_status ∈ {FRESH, STALE}` and `exception_valid`.

**The action check is evaluated BEFORE units and exceptions.** An exception can **never** grant an action absent from `actor.allowed_actions`.

`outcome` branches (mutually exclusive):

| condition | `decision` | `reason_code` | `execution_allowed` |
|---|---|---|---|
| `not input_valid` | `DENY` | `DENY_INVALID_INPUT` | `false` |
| `input_valid`, `not action_allowed` | `DENY` | `DENY_ACTION_NOT_ALLOWED` | `false` |
| `input_valid`, `action_allowed`, `not source_available` | `DENY` | `DENY_SOURCE_UNAVAILABLE` | `false` |
| `input_valid`, `action_allowed`, `source_available`, `unit_matches` | `ALLOW` | `ALLOW_UNIT_MATCH` | `true` |
| `input_valid`, `action_allowed`, `source_available`, `not unit_matches`, `exception_applicable_and_valid` | `ALLOW_WITH_EXCEPTION` | `ALLOW_EXCEPTION_APPLIED` | `true` |
| `input_valid`, `action_allowed`, `source_available`, `not unit_matches`, `not exception_applicable_and_valid`, `status == FRESH` | `DENY` | `DENY_UNIT_MISMATCH` | `false` |
| `input_valid`, `action_allowed`, `source_available`, `not unit_matches`, `not exception_applicable_and_valid`, `status == STALE` | `ESCALATE` | `ESCALATE_STALE_ASSIGNMENT` | `false` |

### Summary table

| action allowed | `assignment_status` | unit matches | valid `FRESH` exception | → `decision` |
|---|---|---|---|---|
| (invalid/incoherent input) | — | — | — | `DENY` (`DENY_INVALID_INPUT`) |
| no | — | — | — | `DENY` (`DENY_ACTION_NOT_ALLOWED`) |
| yes | UNAVAILABLE | — | — | `DENY` (`DENY_SOURCE_UNAVAILABLE`) |
| yes | FRESH | yes | (does not change the decision) | `ALLOW` |
| yes | FRESH | no | yes | `ALLOW_WITH_EXCEPTION` |
| yes | FRESH | no | no | `DENY` (`DENY_UNIT_MISMATCH`) |
| yes | STALE | not applicable\* | yes | `ALLOW_WITH_EXCEPTION` |
| yes | STALE | not applicable\* | no | `ESCALATE` (held) |

\* With `STALE` the unit is not compared, because the assignment data itself is not trustworthy — hence a `FRESH` exception is always looked for, or the request is escalated.

### How the consumer must handle decisions

The PEP must handle the four decisions **explicitly** (not collapse them into a boolean):

- **`ALLOW`** → execute.
- **`ALLOW_WITH_EXCEPTION`** → execute, but at minimum **log the applied exception**, preserving `reason_code` and `applied_exception_id`.
- **`DENY`** (any `reason_code`) → deny.
- **`ESCALATE`** → **hold** the operation and trigger review/retention; do **not** silently turn it into an ordinary denial.

In the Python integration, `access_allowed()` returns `True` only for `ALLOW` and `False` for any `DENY`; `ALLOW_WITH_EXCEPTION` and `ESCALATE` raise `DecisionRequiresExplicitHandling` to prevent the API from hiding these cases. The audit system and the review workflow are the consumer's responsibility; this project only avoids concealing them.

---

## Python integration (client boundary)

The `freshauthz.py` module wraps `opa eval` via subprocess and adds guarantees at the **Python boundary**:

- **Response ↔ request binding.** The result is additionally validated against the original input: `actor_id`, `record_id`, `assignment_status` and `evaluated_at` must correspond to the request; in `ALLOW_WITH_EXCEPTION`, `applied_exception_id` must be the `exception.id` that was sent; otherwise it is `null`. A response reflecting a different actor, record, state, exception or instant is not trusted. For `DENY_INVALID_INPUT`, the **sanitised** echoes are compared (valid string → echoed; wrong type/absent → `null`; state outside the enum → `null`).
- **Output normalisation.** **Unknown fields** returned by OPA **take no part in the decision and are stripped at the Python boundary**: the consumer only receives the contractual keys. They are not rejected automatically, so that compatible policy changes remain possible.
- **Strict serialisation.** The input root must be an object; it is serialised with `allow_nan=False`. `NaN`, infinities, non-serialisable objects and non-object roots are rejected in a controlled way (`EvaluationError`), without raw exceptions.
- **Safe OPA execution.** The binary is resolved once to a verified **absolute path** (exists, is a file, is executable) and run without a shell. `opa_path=` can be injected **for testing/development only**.
- **Bundled policy.** Normal use runs the policy shipped alongside the module. A **custom policy** (`policy_path=`) is **for testing or development only** and requires `allow_custom_policy=True`; it must never come from client data. `policy_sha256()` is exposed for audit/diagnostics (it is not a complete integrity system).
- **Minimal audit.** `build_audit_record()` first revalidates the response against the contract and the original request, and then builds (without persisting) a dictionary with actor, unit, record, action, state, decision, `reason_code`, `execution_allowed`, `applied_exception_id`, `approved_by`, `evaluated_at`, version and SHA-256 of the policy. The consumer decides where to store it.
- **Performance limitation.** Each evaluation spawns an `opa eval` **subprocess**; suitable for moderate volumes, not for very high-throughput paths. An OPA Server/sidecar or bundles are **out of scope** for this version.

## Changelog

### 5.0.2

Tests and documentation only. The decision logic, the reason codes and the input/output schema are unchanged; `policy_version` now reports `5.0.2`.

- Remaining Spanish names of local variables and test values in `policy_test.rego` and `test_freshauthz.py` renamed to English.
- README: `ALLOW_WITH_EXCEPTION` executes and the consumer must log the exception; the policy itself does not log.
- The 5.0.1 entry below no longer lists the Python requirement among the corrections: the earlier wording was correct and was only reworded.

### 5.0.1

Documentation and CI only. The decision logic, the reason codes and the input/output schema are unchanged; `policy_version` now reports `5.0.1`.

- The version history of earlier, unpublished versions was removed from this contract and from the header of `policy.rego`.
- CI now verifies the OPA binary against a SHA-256 checksum pinned in the workflow.
- Contract wording aligned with the maturity label: this is a reference implementation.
- README corrections: copyright notice, coverage figure and CI description. The Python requirement was reworded.

### 5.0.0

First public version. Earlier versions were internal and are not published.
