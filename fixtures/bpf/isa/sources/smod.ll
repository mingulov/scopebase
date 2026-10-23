; TC03 ISA vector: signed remainder (MOD opcode with off=1, e.g. 0x9f).
; -mcpu=v4 only; clean selection failure below v4.
; Emitted with: llc -march=bpfel -mcpu=v4 -filetype=obj -o smod.o smod.ll
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-none"
define dso_local i64 @prog(ptr %ctx, i64 %d) #0 section "socket" {
entry:
  %v = load i64, ptr %ctx, align 8
  %q = srem i64 %v, %d
  ret i64 %q
}
attributes #0 = { nounwind "target-cpu"="v4" }
