# Compatibility, errors and structural documentation

The [versioning policy](../versioning.md), [shared interfaces](interfaces.md) and [evidence contract](evidence.md) are normative inputs. This document adds documentation consistency rules. A structural pass cannot certify arbitrary prose, implementations, installed examples or runtime support.

## Error, effect and owner contracts

| Domain | Stable meaning and owner |
|---|---|
| linux.stage / linux.reason | Linux operation stage and reason, including LimitExceeded's existing LimitKind payload; LX owns the actual LinuxError. Denied differs from Unavailable. |
| bpf.kind / bpf.stage | BPF operation category and stage; BP/TC own actual operations and owner-bearing effects. |
| capture.contract / capture.replay | Pure capture semantic failures and strict replay framing failures; CP owns validation and decoders. |

These six catalogs are separate and ordered, with their exact category identities in [schema-versions.json](../../profiles/schema-versions.json). They are not aliases, a shared error enum or a replacement for native numeric status assignments. Linux categories come from the named specification sentences; BPF/capture categories come from uniquely named simple Rust enums in their specification fences. Changed/missing/ambiguous selector syntax is refused, rather than guessed. The tool detects ordered source/catalog drift; it does not prove those categories are implemented.

Preserve operation, stage, source errno, typed reason, incurred charges, partial observations and explicit cleanup/owner outcomes. Callers use getters/categories rather than parsing Display. EPERM/EACCES at BPF_PROG_LOAD has multiple possible causes; operation/stage/verifier evidence must retain ambiguity. Unknown cause stays unknown in its capability record. Do not add Unknown to an unrelated error enum or infer a source-license failure from load refusal.

Report byte, work, memory, wait and resource bounds separately. Cooperative deadlines do not guarantee interruption of syscalls, mutex waits or callbacks. Ambiguous effects prohibit blind retries. Native owners and pool charges survive pending cleanup; Drop, descriptor closure, cancellation and a quiet period cannot certify retirement. Each component retains its own concurrency/fork/lock policy. Reports and neutral values create no authority; live actions require their owning constructor and retained domain-specific object.

## Registry and checker contract

`profiles/schema-versions.json` has exactly schema_version (`1.0.0`), kind (`documentation_contract_registry`), domains and error_domains. Eleven required version-domain declarations and six error domains cannot silently shrink. Domain fields are id, encoding, version, state, owner_task and source. Semver versions use canonical three-component strings, majors canonical positive-decimal strings, and per_artifact versions null. Planned states carry no implementation/release claim; only documentation-registry is an implemented_tool_schema. Error-domain fields are id, source, selector and ordered unique categories. Owners, source paths and selectors follow the frozen SB03 declarations.

Each of the six fixed policy/template documents and each concrete `docs/issues/*.md` (excluding README/TEMPLATE selection duplication) has exactly one scopebase-doc fenced JSON object. Its exact fields are schema_version (integer 1), id, mode, owner_task, requirements, versions, errors, profiles, subject_kind, authority_claim and execution. IDs are unique ASCII alphanumeric followed by ASCII alphanumeric/dot/underscore/hyphen, up to 96 bytes. Owners/requirements/base profiles resolve from existing traceability; extension IDs cannot masquerade as profiles.

Modes are contract, template or illustrative. Version references are unique domain/version objects with exact registered values; null explicitly defers concrete revisions to their owning artifacts. Error references are unique domain/category pairs from the source-checked catalog. Profile references are unique id/claim objects whose claim must be planned. There is no accepted supported/qualified-input interface in SB03; TT10/RL03 must explicitly add that later. Execution is not_applicable or not_run, including illustrative examples. Subject report, observation or policy requires authority_claim none; live_owner requires requires_constructor and its specified constructor, never an owner serialized by this block.

User/developer guide subsections each require their own H3 checklist. Issue records use the template's complete ordered H2 checklist. Sections need nonempty text; concrete issues reject standalone TODO, TBD or <fill>. Honest unresolved text names UNKNOWN, reason, owner and exit criterion and never establishes readiness. Template placeholders are instructions to future authors. Ordinary prose remains a human review obligation.

Run `python3 tools/planning/check_docs.py [--root PATH] [--registry PATH] [--format json|text]`. Defaults select the script's repository, root-relative registry above and JSON. Explicit fixture roots still require the full document set. No selection flag narrows a success claim. The importable validate(root, registry) returns sorted diagnostics; main(argv=None) supplies the CLI.

Checks use Python standard-library parsing and the existing duplicate-member/link helpers. They read local explicit files only, with containment checks before reads: no subprocess, Git/donor verification, network, Markdown execution or code execution. External links remain unverified. Simple inline/reference local links use the existing heading-anchor grammar; arbitrary Markdown rendering is outside this bounded tool.

Limits are 1 MiB per JSON file/block, 2 MiB per Markdown document, 256 distinct checked Markdown files, 256 documentation records, 256 issue records, 256 entries per checked collection/link list. Reads stop at limit+1; invalid over-limit collections are not traversed. At most 128 sorted diagnostics are printed, with omitted_errors counting the remainder. A byte bound is not a wall-clock interruption guarantee for filesystem IO.

JSON output has exactly schema_version (1), status (VALID or INVALID), qualification (not_evaluated), checked_documents (sorted root-relative document paths), errors and omitted_errors, then a newline. Diagnostics have exactly code, path, record and message, sorted by path/record/code/message. There are no timestamps, scratch-root paths or host environment fields. Text output prints diagnostics and `VALID/INVALID; qualification=not_evaluated`. Exit 0 means valid structure; 3 means invalid content/IO/bounds; 64 means usage. Empty/missing required inputs never pass through zero checked documents.

## Validation and later consumers

The synthetic fixture suite pairs each mutation with a passing twin and independent literal diagnostic: unknown versions/categories, category drift, profile overclaim, fabricated authority, false execution, dangling references, missing fields/sections, strict framing, link/path escapes and exact bounds. Run `python3 -m unittest discover -s tools/planning/tests -p 'test_docs.py' -v` and the existing planning baseline check. These are development-tool tests, with qualification not_evaluated.

T0 logic, T1 models, T2 final objects, T3 host operations, T4 live kernels and T5 distributed consumers remain distinct. Expected-refusal assertions may pass while a capability is denied or unknown; missing required fixture/activity/cleanup is incomplete. TT01 owns executable manifests, TT02 report verdicts, TT07 installed routes, TT10 closure and RL03 generated support. A document example, source selection, file pilot or dependency fixture client cannot close their package/mapped-image/SDK/native readiness gates.

```scopebase-doc
{
  "schema_version": 1,
  "id": "compatibility",
  "mode": "contract",
  "owner_task": "SB03",
  "requirements": [
    "SB-R06",
    "SB-R13",
    "SB-R18"
  ],
  "versions": [
    {
      "domain": "documentation-registry",
      "version": "1.0.0"
    },
    {
      "domain": "neutral-semantic",
      "version": "1"
    },
    {
      "domain": "native-abi",
      "version": "1"
    },
    {
      "domain": "native-wire",
      "version": "1"
    }
  ],
  "errors": [
    {
      "domain": "linux.reason",
      "category": "Denied"
    },
    {
      "domain": "linux.reason",
      "category": "Unavailable"
    },
    {
      "domain": "bpf.kind",
      "category": "Denied"
    },
    {
      "domain": "capture.replay",
      "category": "VersionMismatch"
    }
  ],
  "profiles": [
    {
      "id": "held-file-v1",
      "claim": "planned"
    }
  ],
  "subject_kind": "policy",
  "authority_claim": "none",
  "execution": "not_applicable"
}
```
