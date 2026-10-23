; TC03 ISA vector: 32-bit jump class (BPF_JMP32, 0x06).
; NOTE: llc 21.1.8 emits JMP32 even at -mcpu=generic; preset name alone
; cannot prove a baseline-only object (donor H30 preset warning).
; Emitted with: llc -march=bpfel -mcpu=v3 -filetype=obj -o jmp32.o jmp32.ll
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-none"
define dso_local i64 @prog(ptr %a, ptr %b) #0 section "socket" {
entry:
  %x = load i32, ptr %a, align 4
  %y = load i32, ptr %b, align 4
  %c = icmp ult i32 %x, %y
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 0
}
attributes #0 = { nounwind "target-cpu"="v3" }
