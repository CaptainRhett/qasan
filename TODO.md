# TODOs

+ thread-safe interval tree for allocation tracking
+ update to the current AFL++ QEMU mode, this is a bit old
+ ~~flags to disable shadow call stack~~
+ ~~shadow call stack for other archs (not only x86)~~
+ stack-use-after-return detection
+ backdoor instruction for other archs (not only x86)


diff --git a/accel/tcg/cpu-exec.c b/accel/tcg/cpu-exec.c
diff --git a/accel/tcg/cputlb.c b/accel/tcg/cputlb.c
diff --git a/accel/tcg/tcg-runtime.c b/accel/tcg/tcg-runtime.c
diff --git a/accel/tcg/tcg-runtime.h b/accel/tcg/tcg-runtime.h
diff --git a/accel/tcg/translate-all.c b/accel/tcg/translate-all.c
diff --git a/accel/tcg/user-exec.c b/accel/tcg/user-exec.c
diff --git a/bsd-user/syscall.c b/bsd-user/syscall.c
diff --git a/exec.c b/exec.c
diff --git a/fpu/softfloat.c b/fpu/softfloat.c
diff --git a/linux-user/elfload.c b/linux-user/elfload.c
diff --git a/linux-user/main.c b/linux-user/main.c
diff --git a/linux-user/signal.c b/linux-user/signal.c
diff --git a/linux-user/syscall.c b/linux-user/syscall.c
diff --git a/target/arm/translate-a64.c b/target/arm/translate-a64.c
diff --git a/target/arm/translate.c b/target/arm/translate.c
diff --git a/target/i386/fpu_helper.c b/target/i386/fpu_helper.c
diff --git a/target/i386/ops_sse.h b/target/i386/ops_sse.h
diff --git a/target/i386/translate.c b/target/i386/translate.c
diff --git a/tcg/tcg-op.c b/tcg/tcg-op.c
diff --git a/tcg/tcg-op.h b/tcg/tcg-op.h
diff --git a/tcg/tcg.c b/tcg/tcg.c
diff --git a/vl.c b/vl.c






