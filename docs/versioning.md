# Versioning and advertised support

These are compatibility rules, not release or support receipts. The [registry](../profiles/schema-versions.json) is documentation metadata; planned entries do not imply released artifacts. [Compatibility](contracts/compatibility.md) defines exact document references and category semantics.

## Independent version domains

Rust packages start independently at `0.1.0`; family lockstep is unnecessary. Neutral semantics, capture JSON replay, native ABI, native wire, run-report schema, case-catalog schema, individual case revisions, fixture revisions and support-profile versions are separate identities. Equal initial numbers imply no conversion or equivalence. Per-artifact registry values are null until the owning artifact supplies its revision; SB03 assigns no speculative case/fixture revisions and copies no TT profile dependency graph.

During major zero, changing or removing a public API, category meaning, accepted-input contract, effect/ownership guarantee or previously advertised support contract requires the next minor release. Patches preserve the advertised contract. A correction to an already documented refusal/invariant is a patch candidate only with the retained regression, affected-client analysis and review. Silently tightening formerly promised input is not a compatible patch.

An additive API or non-exhaustive Rust enum variant can be compatible only while existing callers, accepted inputs and effects remain valid. Fixed wire discriminants are not extensible Rust enum variants. Stable structured category names and meanings are public behavior; Display text is diagnostic. Renaming or remapping a category requires a public behavior change review.

Owning decoders explicitly refuse incompatible unknown majors and unrecognized required fields/tags. Exact-v1 neutral and native contracts stay exact. An optional extension needs a named bounded contract, owner and tests before adoption. SB03's registry reader accepts exactly `1.0.0`, including minor/patch, and document references use exact registered versions. This tool rule does not override another decoder's compatibility semantics.

Case, fixture or oracle changes invalidate affected evidence without necessarily changing Rust APIs. Changing required profile cases/cells/support obligations requires a new profile version before environment discovery. Missing cells never justify weakening the current profile. Historical receipts retain their old versions and bindings.

## Compiler and target policy

Initial target is `x86_64-unknown-linux-gnu`, edition 2021; proposed package compiler floor is `1.88.0`, selected current compiler is `1.98.1`. The accepted [SB02 dependency record](dependencies.md) binds the actual compiler/API/feature trials. Its latest causal probe report selected 6/22 compiler cells with 80 stage IDs omitted; older full reports remain historical. The root workspace is empty. These trials establish only their stated probe scope, not package-wide MSRV or runtime support. SB03 performs no compiler execution.

To change the floor, amend the specification before adoption, explain the affected API/dependency need, review actual downstream clients, lockfiles and feature unions, and run both selected compiler checks on affected artifacts. Preserve regressions and exact results. A dependency error does not authorize silently raising MSRV. Do not infer Arm, musl or other-endian runtime support from x86 success; alternative-width/endian vectors are a separate tier.

## Host and BPF environment selection

Initial host obligations include exact provisioned Linux 5.15/6.12 and a pinned current control. The controller's [source-selection record](contracts/host-kernel-source-selection.md) selects 5.15.223, 6.12.113 and 7.2.11 with attributed expected archive hashes. This is a bound source decision. Archive acquisition/checksum/signature verification, configuration/compiler/image binding and runtime qualification remain NOT_RUN or pending TT04 as that record states. SB03 does not refresh or certify upstream release information.

Each BPF profile separately selects oldest/current/distro-backport/reproducer/refusal cells and actual final-object ISA/helper/BTF/verifier/attach requirements before environment discovery. There is no universal BPF kernel floor or uname-only admission. Current loading does not establish semantics or justify removing padding, private-stack, linker or old-verifier workarounds. Extra affected-old cells remain required even when a modern patch belongs to their major/minor line. Per-file source grants, final ELF license bytes and loader-supplied runtime bytes are independent checks.

```scopebase-doc
{
  "schema_version": 1,
  "id": "versioning",
  "mode": "contract",
  "owner_task": "SB03",
  "requirements": [
    "SB-R13",
    "SB-R18",
    "SB-R12"
  ],
  "versions": [
    {
      "domain": "rust-package",
      "version": "0.1.0"
    },
    {
      "domain": "neutral-semantic",
      "version": "1"
    },
    {
      "domain": "capture-replay",
      "version": "1"
    },
    {
      "domain": "native-abi",
      "version": "1"
    },
    {
      "domain": "native-wire",
      "version": "1"
    },
    {
      "domain": "run-report",
      "version": "1"
    },
    {
      "domain": "case-catalog",
      "version": "1"
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
    },
    {
      "domain": "documentation-registry",
      "version": "1.0.0"
    }
  ],
  "errors": [],
  "profiles": [],
  "subject_kind": "policy",
  "authority_claim": "none",
  "execution": "not_applicable"
}
```
