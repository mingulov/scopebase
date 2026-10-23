; TC04 atomic RMW vector: live-result 64-bit add (H29 wrong-old-value shape).
; Donor mechanism (p11scope-ws w000 @ 6f97aa47, frozen tree):
; evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py lines 15-25
; (i64 initial=0x100000035/operand=0x10000000D) and lines 26-40 (live body).
; Decimal spellings below match the donor template values; fresh emission
; input, not a copy. Grant: OWNER-2026-10-23.
; Emitted with: timeout 20 llc -march=bpfel -mcpu=v3 -O2 -filetype=obj -o objects-atomic/rmw-add64-live.o sources-atomic/rmw-add64-live.ll
; llc 21.1.8 emits a NON-fetch XADD here (imm=0x00): the H29 accepted-but-wrong
; shape for 64-bit live add.
target triple = "bpfel"
define i32 @oracle(ptr %context) section "socket" {
  %cell = alloca i64, align 8
  store volatile i64 4294967349, ptr %cell, align 8
  %old = atomicrmw add ptr %cell, i64 4294967309 monotonic, align 8
  %old_ok = icmp eq i64 %old, 4294967349
  %old_bit = zext i1 %old_ok to i32
  %new = load volatile i64, ptr %cell, align 8
  %new_ok = icmp eq i64 %new, 8589934658
  %new_bit = select i1 %new_ok, i32 2, i32 0
  %result = or i32 %old_bit, %new_bit
  ret i32 %result
}
