; TC04 atomic RMW vector: unused-result 32-bit add (dead control).
; Donor mechanism (p11scope-ws w000 @ 6f97aa47, frozen tree):
; evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py lines 26-40
; (dead body: new-value check only, expected retval bit 2). Fresh emission
; input, not a copy. Grant: OWNER-2026-10-23.
; Emitted with: timeout 20 llc -march=bpfel -mcpu=v3 -O2 -filetype=obj -o objects-atomic/rmw-add32-dead.o sources-atomic/rmw-add32-dead.ll
; Non-fetch XADD (imm=0x00) is CORRECT here: the result is unused.
target triple = "bpfel"
define i32 @oracle(ptr %context) section "socket" {
  %cell = alloca i32, align 4
  store volatile i32 53, ptr %cell, align 4
  %old = atomicrmw add ptr %cell, i32 13 monotonic, align 4
  %new = load volatile i32, ptr %cell, align 4
  %new_ok = icmp eq i32 %new, 66
  %new_bit = select i1 %new_ok, i32 2, i32 0
  ret i32 %new_bit
}
