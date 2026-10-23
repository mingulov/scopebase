; TC03 ISA vector: load-acquire (STX BPF_ATOMIC with imm=BPF_LOAD_ACQ,
; e.g. 0xdb imm=0x100). -mcpu=v4 only.
; WARNING: llc 21.1.8 hangs in selection for this input below v4; do not
; re-emit at generic/v1/v2/v3 without a timeout. Recorded 2026-10-23.
; Emitted with: llc -march=bpfel -mcpu=v4 -filetype=obj -o acq.o acq.ll
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-none"
define dso_local i64 @prog(ptr %ctx) #0 section "socket" {
entry:
  %v = load atomic i64, ptr %ctx acquire, align 8
  ret i64 %v
}
attributes #0 = { nounwind "target-cpu"="v4" }
