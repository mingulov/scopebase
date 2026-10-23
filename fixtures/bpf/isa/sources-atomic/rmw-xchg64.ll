; TC04 atomic RMW vector: live-result 64-bit exchange (fetch control).
; Donor case family (p11scope-ws w000 @ 6f97aa47, frozen tree):
; evidence/llvm-toolchain-review-20260922/kernel-oracle/cases.json lines 1-142
; (28-case op/width/live-dead matrix); xchg is the always-fetch RMW control
; with old=initial/new=operand. Fresh emission input, not a copy.
; Grant: OWNER-2026-10-23.
; Emitted with: timeout 20 llc -march=bpfel -mcpu=v3 -O2 -filetype=obj -o objects-atomic/rmw-xchg64.o sources-atomic/rmw-xchg64.ll
; llc 21.1.8 emits XCHG with fetch (imm=0xe1) at v3.
target triple = "bpfel"
define i32 @oracle(ptr %context) section "socket" {
  %cell = alloca i64, align 8
  store volatile i64 4294967349, ptr %cell, align 8
  %old = atomicrmw xchg ptr %cell, i64 4294967309 monotonic, align 8
  %old_ok = icmp eq i64 %old, 4294967349
  %old_bit = zext i1 %old_ok to i32
  %new = load volatile i64, ptr %cell, align 8
  %new_ok = icmp eq i64 %new, 4294967309
  %new_bit = select i1 %new_ok, i32 2, i32 0
  %result = or i32 %old_bit, %new_bit
  ret i32 %result
}
