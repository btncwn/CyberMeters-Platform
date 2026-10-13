/* SPDX-License-Identifier: Apache-2.0
 * After loading trust and crypto, the assessment child can only use its pipes.
 * The parent independently enforces network scope, deadlines and budgets.
 */
#ifndef CM_TLS_SANDBOX_H
#define CM_TLS_SANDBOX_H
#if defined(__linux__)
#include <stddef.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#define CM_ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_##n, 0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
static int cm_sandbox(void) {
#if defined(__x86_64__)
#define CM_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define CM_ARCH AUDIT_ARCH_AARCH64
#else
    return 0;
#endif
    struct sock_filter rules[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, CM_ARCH, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* read only stdin; write only stdout. No other inherited descriptor. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read, 0, 4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_write, 0, 4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 1, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        CM_ALLOW(exit), CM_ALLOW(exit_group), CM_ALLOW(brk), CM_ALLOW(mmap),
        CM_ALLOW(munmap), CM_ALLOW(mprotect), CM_ALLOW(madvise),
        CM_ALLOW(clock_gettime), CM_ALLOW(gettimeofday), CM_ALLOW(getpid),
        CM_ALLOW(gettid), CM_ALLOW(futex), CM_ALLOW(getrandom),
        /* glibc may query memory size during OpenSSL allocation on Linux. */
        CM_ALLOW(sysinfo),
        CM_ALLOW(rt_sigaction), CM_ALLOW(rt_sigprocmask), CM_ALLOW(rt_sigreturn),
        CM_ALLOW(sigaltstack), CM_ALLOW(ppoll), CM_ALLOW(sched_yield),
#if defined(__x86_64__)
        CM_ALLOW(poll), CM_ALLOW(time),
#endif
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS)
    };
    struct sock_fprog program = { (unsigned short)(sizeof(rules)/sizeof(rules[0])), rules };
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
           prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
}
#else
static int cm_sandbox(void) { return 0; }
#endif
#endif
