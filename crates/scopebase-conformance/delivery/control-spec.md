# TT07 delivery bad-control specification (frozen v1)

Registered control source for `TT07.closure` and `TT07.binding` under the
`operator-delivery-v1` profile.

Known-bad controls for the delivery route: a tampered closure file must be
refused as a broken package before execution; a missing closure file must
be refused as incomplete with no receipt; a renamed subject must never be
certified; a tampered receipt seal must fail verification. Each control has
a passing twin in the operator test suite asserting `value.equal`.
