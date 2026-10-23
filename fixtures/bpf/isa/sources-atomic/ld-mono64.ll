; TC04 AtomicLoad selector vector: relaxed 64-bit load at v4 (H31).
; Donor reproducer (p11scope-ws w000 @ 6f97aa47, frozen tree):
; llvm-bpf-atomic-load-report.md lines 22-29 (minimal IR: load atomic i64
; monotonic, align 8). Adapted to a named socket section for the TC03
; inspector; semantics unchanged. Grant: OWNER-2026-10-23.
; Emitted with: timeout 20 llc -march=bpfel -mcpu=v4 -O2 -filetype=obj -o objects-atomic/ld-mono64.o sources-atomic/ld-mono64.ll
; llc 21.1.8 at v4 lowers this to an ORDINARY u64 load plus exit (no acquire
; opcode). Below v4 the same input aborts selection (recorded refusal, not
; re-probed per run). WARNING: never re-emit load-atomic inputs below v4
; without a timeout; acquire below v4 HANGS llc 21.1.8 (TC03 record).
target triple = "bpfel"
define i64 @f(ptr align 8 %p) section "socket" {
  %v = load atomic i64, ptr %p monotonic, align 8
  ret i64 %v
}
