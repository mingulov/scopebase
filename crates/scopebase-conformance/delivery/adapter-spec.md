# TT07 delivery adapter specification (frozen v1)

Registered case source for `TT07.closure` and `TT07.binding` under the
`operator-delivery-v1` profile.

The delivery adapter serves two T0 literal steps:

- `sha256-hex`: hashes one input slot with SHA-256 and reports the lowercase
  hex digest as the step value.
- `subject-coords`: reports one UTF-8 input slot verbatim as the step value.

Unknown schemas or operations are dialect refusals (`unsupported_schema`
with no progress); missing input slots are `unavailable`. The adapter
registers no effects and retires cleanly. Its subject binding carries fixed
package coordinates plus measured host/target and executable bytes.
