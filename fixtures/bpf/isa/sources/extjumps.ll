; TC03 ISA vector: signed conditional jumps (JSGT here; family covers
; JSGT/JSGE/JSLT/JSLE in JMP/JMP32 classes).
; NOTE: llc 21.1.8 emits signed jumps even at -mcpu=generic.
; Emitted with: llc -march=bpfel -mcpu=v3 -filetype=obj -o extjumps.o extjumps.ll
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-none"
define dso_local i64 @prog(ptr %ctx) #0 section "socket" {
entry:
  %v = load i64, ptr %ctx, align 8
  %c = icmp slt i64 %v, 0
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 0
}
attributes #0 = { nounwind "target-cpu"="v3" }
