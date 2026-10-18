# BPF

```rust
pub enum ErrorKind { InvalidInput, Malformed, Incompatible, Unsupported, Denied, Disappeared, Changed, LimitExceeded, Overflow, Backend, Poisoned }
pub enum Stage { Admission, Metadata, Allocate, Read, Attach, Drain, Retire, BtfQuery, Compile, Inspect, Execute }
```
