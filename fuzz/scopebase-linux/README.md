# LX05 proc parser fuzz project

This is a separate Cargo workspace with two libFuzzer targets. It depends on the
candidate `scopebase-linux` path crate, uses `libfuzzer-sys =0.4.13`, and keeps an
independently authored reference parser in `oracle/proc_reference.rs`. Neither
binary is part of the normal product workspace or package closure.

`corpus/manifest.json` binds all source seeds and literal expected acceptance.
It retains the initial generic mixed-row population and adds the exact A3
three-row positive and four-row `broken` negative populations. The draft
`maps/line-512` seed has a malformed inode because its padding is appended to
the inode token; its expected outcome was corrected to refusal without changing
that seed's bytes.

`Cargo.lock` and `combined-graph.json` bind the merged ScopeBase and libFuzzer
graph. Root completed locked/offline metadata validation after composing the
existing admitted `rustix 1.1.5` and `bitflags 2.13.2` sources with the earlier
fuzz admission. No source was fetched or substituted for that qualification.

`preparation-index.json` and `controls/a3-control.json` preserve the worker's
pre-admission blocked snapshot. They exclude the index itself from its file
list to avoid a self-hash cycle. `qualification.md` records the later root
admission and results: the exact A3 positive/mutant/restored control, six
package cells with twelve source/archive helper receipts, and two independent
10,000-run address-sanitized campaigns. These runs qualify only the frozen
LX05 candidate and bounded profiles described there.
