; TC03 ISA vector: sign-extending load (LDX BPF_MEMSX, e.g. 0x89).
; Unlocked at -mcpu=v4; falls back to plain load plus shifts below v4.
; Emitted with: llc -march=bpfel -mcpu=v4 -filetype=obj -o memsx.o memsx.ll
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-none"
define dso_local i64 @prog(ptr %ctx) #0 section "socket" {
entry:
  %p = getelementptr i16, ptr %ctx, i64 2
  %v = load i16, ptr %p, align 2
  %e = sext i16 %v to i64
  ret i64 %e
}
attributes #0 = { nounwind "target-cpu"="v4" }
