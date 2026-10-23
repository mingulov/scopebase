; TC04 atomic RMW vector: 64-bit compare-and-swap, expected-hit control.
; Donor mechanism (p11scope-ws w000 @ 6f97aa47, frozen tree):
; evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py lines 41-53
; (CAS body: comparator initial on hit, old=initial/new=operand). Fresh
; emission input, not a copy. Grant: OWNER-2026-10-23.
; Emitted with: timeout 20 llc -march=bpfel -mcpu=v3 -O2 -filetype=obj -o objects-atomic/rmw-cas64-hit.o sources-atomic/rmw-cas64-hit.ll
; llc 21.1.8 emits CMPXCHG with fetch (imm=0xf1) at v3.
target triple = "bpfel"
define i32 @oracle(ptr %context) section "socket" {
  %cell = alloca i64, align 8
  store volatile i64 4294967349, ptr %cell, align 8
  %pair = cmpxchg ptr %cell, i64 4294967349, i64 4294967309 monotonic monotonic, align 8
  %old = extractvalue { i64, i1 } %pair, 0
  %old_ok = icmp eq i64 %old, 4294967349
  %old_bit = zext i1 %old_ok to i32
  %new = load volatile i64, ptr %cell, align 8
  %new_ok = icmp eq i64 %new, 4294967309
  %new_bit = select i1 %new_ok, i32 2, i32 0
  %result = or i32 %old_bit, %new_bit
  ret i32 %result
}
