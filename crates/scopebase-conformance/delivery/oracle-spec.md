# TT07 delivery oracle specification (frozen v1)

Registered oracle source for `TT07.closure` and `TT07.binding` under the
`operator-delivery-v1` profile.

The literal oracle compares observation steps to the frozen expected vector
byte-for-byte: same schema version, observation/expected kind pair and equal
step lists pass `value.equal`; anything else fails. Adapter dialect
refusals (`unsupported_schema`) are judged `not_judged` with unknown
capability. The oracle never reads adapter inputs, only expected evidence
and observed outcomes.
