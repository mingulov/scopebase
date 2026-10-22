# BP02 preserved map-reader defects and boundaries

KryProbe's frozen mapops fix sizes perCPU reads by all possible CPUs, including
offline lanes, with eight-byte slot rounding. Using online count or raw value
size can underallocate a lengthless BPF kernel copy. ScopeBase's pure geometry
ports that mechanism; the actual map reader additionally derives geometry from
its retained FD's metadata and internally authenticated kernel sources. The
independent15 geometry vectors, sparse/offline controls, pure geometry mutant,
and real array/hash fixture exercise distinct paths.

libbpf-mojo's selected object-map code refuses bloom membership lookup before
extent/allocation/value copy and commits private scratch only after success.
ScopeBase retains those properties. It performs the metadata query necessary to
learn the actual kind, then refuses unsupported kinds before downstream work.
Partial scratch writes, real hash absence, short/long outputs and failed
postvalidation must leave caller output unchanged.

The selected WHO fix uses88-byte lanes and16-byte keys through lookup, slicing,
decode, checked fold and whole-report construction. Unique marker1 identifies
the inserting lane; zero uid/stack is legitimate, while unmarked zeros are not
observed identity. Latest comm/tid fold independently. Each lane's MAX count
refuses, but a checked final sum exactly MAX is accepted. Decoded-lane storage is
cleared and reused across rows. The seven ported migration tests are producer
models; real BPF race/loss qualification belongs to BP07. Reference120-byte
aggregate/totals and8-byte diagnostic controls retain their distinct policies.
The package's WHO mutant experiments alter a delivered test model. They need
named stale-80 rejection failures and restored positives; a later valid-input
panic is not proof that the active negative was caught. These model results
remain separate from mutations of production-library source.

The new source authority closes donor plain-path trust gaps. A syntactically
valid prefix may be truncated by the page-sized sysfs formatter, so native reads
require length<4095, newline and EOF. Genuine complete roots and constrained
traversal prevent a bind-mounted online list or fake smaller list authorizing a
copy. A retained proc inode is not unique task identity: exact initial
thread-self text plus a fresh original-relative stat read preserves continuity
at checks. Held descriptors and the immutable-mask ABI, rather than before/after
comparison alone, bound native copies.

The first independent implementation review found an aggregate-capacity ordering
gap and an overly broad traversal errno override. The retained regressions
require observed ID overgrant to refuse before source allocation, and held-FD
EXDEV/ELOOP to retain Backend/Read while constrained traversal retains its
specific refusal. Error/output/poisoning assertions and restored twins accompany
the fixes. None of these records itself qualifies a complete runtime profile.
