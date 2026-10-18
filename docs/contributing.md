# User and developer documentation templates

SB03 supplies writing templates. Domain owners fill and compile actual package examples; TT07 delivers installed commands. None of the package examples or operator routes below is implemented or executed by this document. See [versioning](versioning.md), [compatibility](contracts/compatibility.md), [issue template](issues/TEMPLATE.md) and the [existing issue index](issues/README.md).

## User guide template

### Prerequisites

Name exact package/profile, target, compiler, backend, credentials and provisioned environment. Distinguish optional setup from required cells chosen before discovery. Default host use must not require a BPF compiler or privilege changes.

### Package and installed route

NOT_IMPLEMENTED. Owner: domain package task and TT07. Exit criterion: actual distributed package-relative fixtures, public developer conformance API and independently installed command run over that package. Replace this instruction with real locations/commands, version/features/backend binding and offline installation instructions after delivery; ordinary downstream cargo test does not run dependency tests.

### Actual consumer binding

Record actual consumer package/version/features/backend/source/build and relevant final-object/compiler identities. The testkit separately resolved copy is not the subject. Name the selected case/fixture/oracle/profile revisions.

### Inputs and effects

State accepted input contracts, caller-controlled calibration and every filesystem/process/namespace/BPF effect. Document partial effects and refusal; preserve application-local privacy/schema/shutdown policy. State default absence of stdout, logger installation and upload.

### Limits and failure meanings

Specify byte, work, memory, wait and resource limits separately, including charges on failure. Give typed stage/reason/source errno and category meaning; Display is diagnostic. Explain Denied versus Unavailable and ambiguous BPF causes without inventing enum variants. Cooperative timeout is not syscall interruption.

### Ownership and cleanup

Identify owning constructors, retained resources, fallible retirement, unresolved custody and outstanding charges. Report data never creates runtime authority. Explain what cancellation and Drop actually do; do not claim cleanup solely from closure or quiet time.

### Concurrency and fork

Use the actual component Send/Sync, lock, reentrancy and caller-fork policy. State the supported new acquisition after exec where required; never infer universal ownership/thread rules from another component.

### Required cases and environments

Name preselected required cases/tiers/cells and independent positive/excluded populations. Record actual filesystem/namespace/denial triggers for advertised mapping support. Missing required fixtures/activity/cleanup remain incomplete; expected-refusal can pass without support.

### Examples and execution status

NOT_IMPLEMENTED / NOT_RUN until the domain owner provides and compiles real examples against distributed bytes. Name owner and exact acceptance command/result binding when available. Keep T0 logic, T1 models, T2 final objects, T3 host, T4 kernels and T5 installed consumers separate. Do not paste speculative APIs or fake successful output.

### Sanitized support report

State opt-in local collection and an explicit caller sanitization step. Default shareable content omits raw paths/content/addresses/PIDs/command lines; preserve typed stage/reason/limits and actual binding. Escape controls, bound messages/total size, record truncation and retain sensitive local detail separately. Sanitization does not imply anonymity or authenticity.

## Developer guide template

### Prerequisites

Name exact package/profile, target, compiler, backend, credentials and provisioned environment. Distinguish optional setup from required cells chosen before discovery. Default host use must not require a BPF compiler or privilege changes.

### Package and installed route

NOT_IMPLEMENTED. Owner: domain package task and TT07. Exit criterion: actual distributed package-relative fixtures, public developer conformance API and independently installed command run over that package. Replace this instruction with real locations/commands, version/features/backend binding and offline installation instructions after delivery; ordinary downstream cargo test does not run dependency tests.

### Actual consumer binding

Record actual consumer package/version/features/backend/source/build and relevant final-object/compiler identities. The testkit separately resolved copy is not the subject. Name the selected case/fixture/oracle/profile revisions.

### Inputs and effects

State accepted input contracts, caller-controlled calibration and every filesystem/process/namespace/BPF effect. Document partial effects and refusal; preserve application-local privacy/schema/shutdown policy. State default absence of stdout, logger installation and upload.

### Limits and failure meanings

Specify byte, work, memory, wait and resource limits separately, including charges on failure. Give typed stage/reason/source errno and category meaning; Display is diagnostic. Explain Denied versus Unavailable and ambiguous BPF causes without inventing enum variants. Cooperative timeout is not syscall interruption.

### Ownership and cleanup

Identify owning constructors, retained resources, fallible retirement, unresolved custody and outstanding charges. Report data never creates runtime authority. Explain what cancellation and Drop actually do; do not claim cleanup solely from closure or quiet time.

### Concurrency and fork

Use the actual component Send/Sync, lock, reentrancy and caller-fork policy. State the supported new acquisition after exec where required; never infer universal ownership/thread rules from another component.

### Required cases and environments

Name preselected required cases/tiers/cells and independent positive/excluded populations. Record actual filesystem/namespace/denial triggers for advertised mapping support. Missing required fixtures/activity/cleanup remain incomplete; expected-refusal can pass without support.

### Examples and execution status

NOT_IMPLEMENTED / NOT_RUN until the domain owner provides and compiles real examples against distributed bytes. Name owner and exact acceptance command/result binding when available. Keep T0 logic, T1 models, T2 final objects, T3 host, T4 kernels and T5 installed consumers separate. Do not paste speculative APIs or fake successful output.

### Sanitized support report

State opt-in local collection and an explicit caller sanitization step. Default shareable content omits raw paths/content/addresses/PIDs/command lines; preserve typed stage/reason/limits and actual binding. Escape controls, bound messages/total size, record truncation and retain sensitive local detail separately. Sanitization does not imply anonymity or authenticity.

Preserve selected donor mechanism/original regressions with independent truth and a known-bad control that reaches the intended semantic assertion. Name affected call sites, upstream inclusion/removal checks and independently useful reference consumers. Use one writer per shared interface/file, isolated outputs and owned resource leases; report new dependencies/exit criteria to the controller.

```scopebase-doc
{
  "schema_version": 1,
  "id": "contributing",
  "mode": "template",
  "owner_task": "SB03",
  "requirements": [
    "SB-R10",
    "SB-R11",
    "SB-R14",
    "SB-R15",
    "SB-R16",
    "SB-R17",
    "SB-R18"
  ],
  "versions": [
    {
      "domain": "rust-package",
      "version": "0.1.0"
    },
    {
      "domain": "case-revision",
      "version": null
    },
    {
      "domain": "fixture-revision",
      "version": null
    },
    {
      "domain": "support-profile",
      "version": null
    }
  ],
  "errors": [],
  "profiles": [],
  "subject_kind": "policy",
  "authority_claim": "none",
  "execution": "not_run"
}
```
