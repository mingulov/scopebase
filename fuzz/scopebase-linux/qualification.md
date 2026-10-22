# LX05 qualification receipts

The post-format continuation ran on 2026-10-22 against candidate base
`e86ff68aff788fad4396dcfb8f8f33013bc2a103` and its preserved uncommitted A3/fuzz
changes. All 68 Rust files match the startup baseline. The production maps
parser remains SHA-256
`76212790b25c2a4db48c84576a1a83830ada1b8fdabbba87c21b5de6b2f46d38`;
both independent-oracle copies remain SHA-256
`28cb7cf07fee04f9af51593bbbaf130acc80685ea42ea1b1914d0b595dbef25e`.
These observed reruns await final independent review and controller acceptance.

- Exact A3 positive, skip-malformed-row mutant, and byte-identical restored
  positive: `.scopebase/controller/finish-candidates-20261018/lx05-a3-final-r2/result.json`,
  SHA-256 `9058be41062042f281eedeeb86ba905529a73bd2b630e0c09547ccb3c7c353f6`.
  Exit codes were 0/101/0; the mutant failed at
  `A3 whole-input refusal after three valid rows`.
- Six compiler/configuration package cells and twelve source/archive helper
  receipts, representing 24 client executions: `.scopebase/controller/finish-candidates-20261018/lx05-qualification-r3/receipts/result.json`,
  SHA-256 `73707b3e1ef25d99f9012d3579b7f1293a8493980a86ef816588dbcf0fa7ee73`.
  All 44 driver commands returned zero. The derived Linux-only gate has
  56 PASS rows, zero FAIL/BLOCKED/NOT_RUN, and SHA-256 `de37b2d28127671703775716baf92b12b97d3598ef371460190b27933ca3cd1d`.
  This is the six-cell affected gate, not a complete twenty-cell matrix.
  The retained archive `.scopebase/controller/finish-candidates-20261018/lx05-qualification-r3/archive/scopebase-linux-0.1.0.crate` has SHA-256 `e54ad4010dc1681fd33c68dcc44adcbfcbb16cf98c42766455406f134260327b`.
- Locked/offline native builds, startup checks, and two 10,000-run ASan
  campaigns: `.scopebase/controller/finish-candidates-20261018/lx05-fuzz-final-r2/result.json`,
  SHA-256 `47488b69ebb45aa5d0664085f980effd97dcae59138292271e2cb79f30923eb3`.
  All six commands returned zero; both engines reported 10,000 runs and no
  crash artifacts. The 241 bound seeds comprise 75 maps/166 mountinfo and
  128 positive/113 active-negative inputs. Cargo child guards contain five
  locked/offline rows per target.
- Rustfmt passes for the 27 parser/package/support/fuzz source files outside
  `tests/ui`: `.scopebase/controller/resume-20261022/lx05/rustfmt-r2-result.json`.
  An exploratory all-files check reported formatting differences in 32
  preserved UI snippets, each byte-identical to the candidate base; its
  diagnosis and failed receipt are retained, and no snippet was rewritten.

All Cargo/native work used the absolute controller-bound shared build lease
with a 1800-second acquisition allowance. The package driver held one outer
lease for its descendants. The immutable prepared scripts, timeout-only
successors, input manifest and inspections are retained under
`.scopebase/controller/resume-20261022/lx05/`.
The fuzz receipt binds cargo-fuzz 0.13.2, nightly 2026-05-20, Clang 18, the
lock, executable project/oracle/corpus bytes, arguments, environments, Cargo
guards, binary hashes and logs. Its `project_files` includes the pre-receipt
versions of these three qualification documents, preserved under that
continuation directory's `pre-rebind-documents/`; only those metadata files
changed after execution. Parser, oracle, fuzz target, lock and seed bytes
remain identical to the executed inputs.

The October 18 A3/package/fuzz receipts remain historical pre-format evidence:
`lx05-a3-final-r1/result.json` (`eddd4f748ad774ca740d00aefcc8d1ec70d82041808c22a2f4aa1a18c58dc884`),
`lx05-qualification-r2/receipts/result.json` (`e1ec3cda1b606b6895bfd703142f6db9304a82916d1e1e2f3369e583ba820e4d`),
and `lx05-fuzz-final-r1/result.json` (`c7f218ad924b65edb219541b6c4aa7b47a71f242b36f3356c35a2da93a4c1995`), all under
`.scopebase/controller/finish-candidates-20261018/`.
Their links remain in `preparation-index.json.previous_superseded_by`.

This qualifies neither live procfs acquisition, filesystem/namespace identity,
retained runtime authority nor a complete runtime/conformance profile.
Final independent review, controller selected-port validation, commit and
integration remain open. No commit or acceptance was made by this worker.
