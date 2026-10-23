; TC03 ISA vector: register sign extension (MOV with nonzero off, e.g.
; 0xbf off=8). Unlocked at -mcpu=v4; shift/mask fallback below v4.
; Emitted with: llc -march=bpfel -mcpu=v4 -filetype=obj -o movsx.o movsx.ll
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-none"
define dso_local i64 @prog(i64 %x) #0 section "socket" {
entry:
  %t = trunc i64 %x to i8
  %e = sext i8 %t to i64
  ret i64 %e
}
attributes #0 = { nounwind "target-cpu"="v4" }
