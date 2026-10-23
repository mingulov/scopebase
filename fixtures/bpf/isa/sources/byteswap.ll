; TC03 ISA vector: byte swap (ALU BPF_END, e.g. 0xdc).
; NOTE: llc 21.1.8 emits BPF_END even at -mcpu=generic.
; Emitted with: llc -march=bpfel -mcpu=v3 -filetype=obj -o byteswap.o byteswap.ll
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-none"
declare i64 @llvm.bswap.i64(i64)
define dso_local i64 @prog(ptr %ctx) #0 section "socket" {
entry:
  %v = load i64, ptr %ctx, align 8
  %s = call i64 @llvm.bswap.i64(i64 %v)
  ret i64 %s
}
attributes #0 = { nounwind "target-cpu"="v3" }
