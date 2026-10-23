; TC03 ISA vector: baseline ALU64/JMP forms only.
; Emitted with: llc -march=bpfel -mcpu=generic -filetype=obj -o base.o base.ll
; Tool pin: ubuntu-llc-21.1.8 (tools/bpf-compat/toolchains.json).
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-none"
define dso_local i64 @prog(ptr %ctx) #0 section "socket" {
entry:
  %v = load i64, ptr %ctx, align 8
  %a = add i64 %v, 1
  ret i64 %a
}
attributes #0 = { nounwind "target-cpu"="generic" }
