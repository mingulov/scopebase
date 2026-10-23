; TC03 ISA vector: 32-bit ALU class (BPF_ALU, 0x04), unlocked at -mcpu=v3.
; Falls back to ALU64 forms at generic/v1/v2.
; Emitted with: llc -march=bpfel -mcpu=v3 -filetype=obj -o alu32.o alu32.ll
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-none"
define dso_local i32 @f(i32 %a, i32 %b) #0 section "socket" {
entry:
  %x = or i32 %a, %b
  %y = xor i32 %x, %a
  %z = add i32 %y, %b
  ret i32 %z
}
attributes #0 = { nounwind "target-cpu"="v3" }
