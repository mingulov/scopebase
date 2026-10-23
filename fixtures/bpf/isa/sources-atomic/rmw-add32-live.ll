; TC04 atomic RMW vector: live-result 32-bit add (H29 wrong-old-value shape).
; Donor mechanism (p11scope-ws w000 @ 6f97aa47, frozen tree):
; evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py lines 26-40
; (live/dead oracle body template, initial=53/operand=13 for i32); this .ll is
; a fresh emission input following that user-authored template, not a copy.
; Grant: OWNER-2026-10-23.
; Emitted with: timeout 20 llc -march=bpfel -mcpu=v3 -O2 -filetype=obj -o objects-atomic/rmw-add32-live.o sources-atomic/rmw-add32-live.ll
; llc 21.1.8 emits a NON-fetch XADD here (imm=0x00): the H29 accepted-but-wrong
; shape. The fetch-restored twin is derived in-test by surgery (see
; fixtures/bpf/isa/atomic-mutants.json).
target triple = "bpfel"
define i32 @oracle(ptr %context) section "socket" {
  %cell = alloca i32, align 4
  store volatile i32 53, ptr %cell, align 4
  %old = atomicrmw add ptr %cell, i32 13 monotonic, align 4
  %old_ok = icmp eq i32 %old, 53
  %old_bit = zext i1 %old_ok to i32
  %new = load volatile i32, ptr %cell, align 4
  %new_ok = icmp eq i32 %new, 66
  %new_bit = select i1 %new_ok, i32 2, i32 0
  %result = or i32 %old_bit, %new_bit
  ret i32 %result
}
