; TC03 ISA vector: runtime license declaration section ("license" holding
; NUL-terminated "GPL"). Baseline code plus license only.
; Emitted with: llc -march=bpfel -mcpu=generic -filetype=obj -o lic.o lic.ll
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-none"
@lic_str = dso_local global [4 x i8] c"GPL\00", section "license", align 1
define dso_local i64 @prog(ptr %ctx) #0 section "socket" {
entry:
  ret i64 0
}
attributes #0 = { nounwind "target-cpu"="generic" }
