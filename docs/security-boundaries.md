# Security, authority and diagnostic boundaries

These are public library behavior requirements under the [project specification](superpowers/specs/2026-10-17-scopebase-design.md#public-behavior-and-security-boundaries), not an implemented runtime or security qualification. See the [authority/evidence contract](contracts/evidence.md) and [compatibility rules](contracts/compatibility.md).

## Local effects and authority

Default libraries emit no stdout/stderr, upload, logger installation or hidden privileged setup. Host-only dependencies do not require BPF/native compilers. Do not silently install compilers or change limits, credentials, signals, namespaces or host policy. Explicit calibration means callers control effects; every advertised calibration branch still needs its actual implementation, tests and documentation. Application privacy, loss, schemas and shutdown policies stay local.

Live file/process/map/link/control actions require the owning admitted constructor and retained object in the correct domain. Serialized reports, hashes, neutral values and deserialized evidence never construct that authority. A pidfd does not freeze exec; an open descriptor does not freeze content. Numeric maps/stat/mount keys and equal BTF names are not universal identity. Process observation and control, task birth/exec and content observations remain distinct.

Retention continues through fallible retirement or explicit unresolved custody, including outstanding pool/resource charges. Drop, cancellation, closed descriptors and quiet polls do not produce retirement receipts. Ambiguous effects disallow blind retry; preserve partial observation, stage/reason/source errno, charges and pending owners. Cooperative timeouts do not interrupt every syscall/callback/mutex or establish worker/link/mapping retirement. Apply each component's actual Send/Sync/fork/lock restrictions; native owners must not be re-admitted by caller-fork metadata.

## Diagnostic privacy and support reports

Opt-in diagnostic access is bounded and controlled locally by the caller. Default shareable reports omit raw paths, captured content, addresses, PIDs and command lines. Keep useful structured operation/stage/reason, limit kinds/charges, version/features/backend and execution/cleanup state. Escape control characters before rendering text or framing JSON; bound individual messages and total report size, explicitly recording truncation and dropped counts. Keep detailed sensitive local data separate.

Sanitization is an explicit caller action. It does not prove anonymity, completeness, authenticity or trusted-host execution. A supplied digest identifies claimed bytes and cannot attest the host or mint a runtime owner. The [guide templates](contributing.md) require authors to state both local detail handling and the actual distributed package/consumer binding. SB03 provides no sanitizer, signing service, remote upload or report decoder.

## Untrusted inputs and honest limits

Keep byte/work/memory/wait/resource bounds distinct and retain incurred charges on refusal. Validate lengths, arithmetic, domains and required versions before allocation/native access under each owning API. JSON duplicate/unknown fields require strict framing; fixed wire discriminants retain the exact native contract. SB02's dependency trials identify concrete seams and gaps; they do not qualify hostile corpora, final objects or live behavior.

Source grants, ELF license and loader runtime license bytes require separate checks. User-owned userspace provisionally uses Apache-2.0, BPF programs GPL-2.0-only, applications GPL-3.0-or-later, and shared project-owned target source Apache-2.0 OR GPL-2.0-only or approved separation. Preserve actual third-party options/notices; there is no project MIT option. An author's old GPL header is distinct from an author-authorized destination grant. Aya target option D03 remains a gate for the affected payload, not unrelated host work. Recognized working runtime GPL bytes such as GPL do not establish source compatibility; SPDX or Dual Apache/GPL is not a substitute for that payload's selected runtime string.

Preserve verifier evidence and ambiguous EPERM/EACCES causes in their own capability record; a successful load proves neither source compatibility nor semantics. Tiers, independent controls, selected required cells and cleanup retain their separate meaning. Report gaps to the controller with capability, dependency and exit criterion. External issues/messages/publication and product migrations require their separate authorization.

```scopebase-doc
{
  "schema_version": 1,
  "id": "security-boundaries",
  "mode": "contract",
  "owner_task": "SB03",
  "requirements": [
    "SB-R06",
    "SB-R14",
    "SB-R18"
  ],
  "versions": [],
  "errors": [
    {
      "domain": "linux.reason",
      "category": "Denied"
    },
    {
      "domain": "linux.reason",
      "category": "CleanupUnresolved"
    },
    {
      "domain": "bpf.kind",
      "category": "Backend"
    }
  ],
  "profiles": [],
  "subject_kind": "policy",
  "authority_claim": "none",
  "execution": "not_applicable"
}
```
