/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook - Ptrace Spoof (fake debug register state)
 *
 * Hooks sys_ptrace to intercept PTRACE_GETREGSET/PTRACE_SETREGSET
 * for NT_ARM_HW_BREAK and NT_ARM_HW_WATCH. Maintains a per-thread
 * "fake register book" so anti-cheat engines see clean state while
 * our real HWBP remain active on the physical CPU.
 *
 * Defenses against:
 * 1. Read registers (GETREGSET) → return fake zeros
 * 2. Write registers (SETREGSET) → store in fake book, don't touch real CPU
 * 3. Overflow test (write 7 BPs) → return -ENOSPC correctly
 * 4. Read-write consistency → fake book is self-consistent
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <kputils.h>
#include <asm/current.h>
#include <hook.h>
#include <ktypes.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

#include "stealth_hook.h"

#ifndef INIT_LIST_HEAD
#define INIT_LIST_HEAD(ptr) do { (ptr)->next = (ptr); (ptr)->prev = (ptr); } while (0)
#endif

/* ptrace request constants */
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205

/* NT types for ARM hardware debug */
#define NT_ARM_HW_BREAK 0x402
#define NT_ARM_HW_WATCH 0x403

/* ARM64 max breakpoints/watchpoints */
#define MAX_HW_BREAKPOINTS 6
#define MAX_HW_WATCHPOINTS 4

/* Kernel function pointers */
extern void *(*kf_vmalloc)(unsigned long size);
extern void (*kf_vfree)(const void *addr);
extern unsigned long (*kf_copy_from_user)(void *to, const void __user *from, unsigned long n);
extern struct task_struct *(*kf_find_task_by_vpid)(pid_t nr);

#define PIDTYPE_TGID_LOCAL 1
static pid_t (*kf_task_pid_nr_ns_local)(struct task_struct *task, int type, void *ns) = 0;

/* Per-thread fake register state */
struct fake_bp_state {
    struct list_head list;
    uint32_t tid;
    uint32_t pid;
    int break_count;
    int watch_count;
    struct {
        uint64_t addr;
        uint32_t ctrl;
    } break_regs[MAX_HW_BREAKPOINTS];
    struct {
        uint64_t addr;
        uint32_t ctrl;
    } watch_regs[MAX_HW_WATCHPOINTS];
};

/* iovec structure for GETREGSET/SETREGSET */
struct sh_iovec {
    uint64_t iov_base;
    uint64_t iov_len;
};

/* ARM hardware debug state (matches kernel's user_hwdebug_state) */
struct sh_user_hwdebug_state {
    uint32_t dbg_info;
    uint32_t pad;
    struct {
        uint64_t addr;
        uint32_t ctrl;
        uint32_t pad2;
    } dbg_regs[16]; /* max possible */
};

static struct list_head ptrace_spoof_list;
static int ptrace_spoof_initialized = 0;
static int ptrace_hooked = 0;
static int ptrace_hook_type = 0; /* 1=fp, 2=inline */

/* Target PIDs to spoof (simple array for now) */
static uint32_t spoof_pids[32];
static int spoof_pid_count = 0;

static void ensure_ptrace_init(void)
{
    if (!ptrace_spoof_initialized) {
        INIT_LIST_HEAD(&ptrace_spoof_list);
        ptrace_spoof_initialized = 1;
    }
}

/* Check if a PID should be spoofed */
static int is_spoofed_pid(uint32_t pid)
{
    for (int i = 0; i < spoof_pid_count; i++) {
        if (spoof_pids[i] == 0 || spoof_pids[i] == pid) return 1;
    }
    return 0;
}

static void resolve_ptrace_symbols(void)
{
    if (!kf_task_pid_nr_ns_local) {
        kf_task_pid_nr_ns_local = (typeof(kf_task_pid_nr_ns_local))
            kallsyms_lookup_name("__task_pid_nr_ns");
        sh_dbg("[ptrace_spoof] symbols: task_pid_nr_ns=%llx find_task=%llx\n",
                (uint64_t)kf_task_pid_nr_ns_local, (uint64_t)kf_find_task_by_vpid);
    }
}

static uint32_t get_target_tgid(uint32_t tid)
{
    struct task_struct *task;

    resolve_ptrace_symbols();
    if (!kf_find_task_by_vpid || !kf_task_pid_nr_ns_local)
        return tid;

    task = kf_find_task_by_vpid((pid_t)tid);
    if (!task)
        return 0;

    return (uint32_t)kf_task_pid_nr_ns_local(task, PIDTYPE_TGID_LOCAL, 0);
}

static int is_spoofed_target(uint32_t tid, uint32_t *tgid_out)
{
    uint32_t tgid = get_target_tgid(tid);

    if (!tgid)
        return 0;
    if (tgid_out)
        *tgid_out = tgid;
    return is_spoofed_pid(tgid);
}

/* Find or create fake state for a thread */
static struct fake_bp_state *get_fake_state(uint32_t tid, uint32_t pid)
{
    struct list_head *pos;
    struct fake_bp_state *state;

    for (pos = ptrace_spoof_list.next; pos != &ptrace_spoof_list; pos = pos->next) {
        state = (struct fake_bp_state *)((char *)pos -
                __builtin_offsetof(struct fake_bp_state, list));
        if (state->tid == tid) return state;
    }

    /* Create new */
    if (!kf_vmalloc) return 0;
    state = (struct fake_bp_state *)kf_vmalloc(sizeof(struct fake_bp_state));
    if (!state) return 0;

    memset(state, 0, sizeof(*state));
    state->tid = tid;
    state->pid = pid;

    state->list.next = ptrace_spoof_list.next;
    state->list.prev = &ptrace_spoof_list;
    ptrace_spoof_list.next->prev = &state->list;
    ptrace_spoof_list.next = &state->list;

    return state;
}

static int count_regs_from_iov(uint64_t iov_len)
{
    if (iov_len <= 8)
        return 0;
    return (int)((iov_len - 8) / 16);
}

static long ptrace_set_fake_regs(struct fake_bp_state *state, int is_break,
                                 struct sh_iovec *iov, int max_count)
{
    struct sh_user_hwdebug_state hw_state;
    uint64_t copy_len = iov->iov_len;
    int requested_count = count_regs_from_iov(iov->iov_len);
    int stored_count = requested_count;
    int active_count = 0;

    if (copy_len > sizeof(hw_state))
        copy_len = sizeof(hw_state);
    if (requested_count > 16)
        requested_count = 16;
    if (stored_count > max_count)
        stored_count = max_count;

    memset(&hw_state, 0, sizeof(hw_state));
    if (kf_copy_from_user(&hw_state, (void __user *)iov->iov_base, copy_len))
        return -14;

    if (is_break)
        memset(state->break_regs, 0, sizeof(state->break_regs));
    else
        memset(state->watch_regs, 0, sizeof(state->watch_regs));

    for (int i = 0; i < stored_count; i++) {
        if (is_break) {
            state->break_regs[i].addr = hw_state.dbg_regs[i].addr;
            state->break_regs[i].ctrl = hw_state.dbg_regs[i].ctrl;
        } else {
            state->watch_regs[i].addr = hw_state.dbg_regs[i].addr;
            state->watch_regs[i].ctrl = hw_state.dbg_regs[i].ctrl;
        }
        if (hw_state.dbg_regs[i].addr || hw_state.dbg_regs[i].ctrl)
            active_count++;
    }

    if (is_break)
        state->break_count = active_count;
    else
        state->watch_count = active_count;

    if (requested_count > max_count)
        return -28;
    return 0;
}

static long ptrace_get_fake_regs(struct fake_bp_state *state, int is_break,
                                 struct sh_iovec *iov, void __user *iov_user,
                                 int max_count)
{
    struct sh_user_hwdebug_state hw_state;
    uint64_t copy_len = iov->iov_len;
    int count = is_break ? state->break_count : state->watch_count;
    int copied;

    memset(&hw_state, 0, sizeof(hw_state));
    hw_state.dbg_info = max_count;

    for (int i = 0; i < count && i < max_count; i++) {
        if (is_break) {
            hw_state.dbg_regs[i].addr = state->break_regs[i].addr;
            hw_state.dbg_regs[i].ctrl = state->break_regs[i].ctrl;
        } else {
            hw_state.dbg_regs[i].addr = state->watch_regs[i].addr;
            hw_state.dbg_regs[i].ctrl = state->watch_regs[i].ctrl;
        }
    }

    if (copy_len > sizeof(hw_state))
        copy_len = sizeof(hw_state);

    copied = compat_copy_to_user((void __user *)iov->iov_base, &hw_state, (int)copy_len);
    if (copied != (int)copy_len) {
        pr_err("[ptrace_spoof] copy hwdebug state failed copied=%d expected=%d base=%llx\n",
               copied, (int)copy_len, iov->iov_base);
        return -14;
    }

    iov->iov_len = copy_len;
    copied = compat_copy_to_user(iov_user, iov, sizeof(*iov));
    if (copied != (int)sizeof(*iov)) {
        pr_err("[ptrace_spoof] copy iovec back failed copied=%d expected=%d iov=%llx\n",
               copied, (int)sizeof(*iov), (uint64_t)iov_user);
        return -14;
    }

    return 0;
}

/*
 * Ptrace syscall hook: intercept GETREGSET/SETREGSET before the kernel
 * touches real ARM64 hardware debug registers.
 */
static void ptrace_hook_before(hook_fargs4_t *args, void *udata)
{
    long request = (long)syscall_argn(args, 0);
    long target_tid = (long)syscall_argn(args, 1);
    long type_or_addr = (long)syscall_argn(args, 2);
    long data = (long)syscall_argn(args, 3);
    struct fake_bp_state *state;
    struct sh_iovec iov;
    uint32_t target_tgid = 0;
    int is_break;
    int is_watch;
    int max_count;

    if (request != PTRACE_GETREGSET && request != PTRACE_SETREGSET)
        return;

    is_break = (type_or_addr == NT_ARM_HW_BREAK);
    is_watch = (type_or_addr == NT_ARM_HW_WATCH);
    if (!is_break && !is_watch)
        return;

    if (!is_spoofed_target((uint32_t)target_tid, &target_tgid))
        return;

    if (!kf_copy_from_user || kf_copy_from_user(&iov, (void __user *)data, sizeof(iov))) {
        args->skip_origin = 1;
        args->ret = -14;
        return;
    }

    max_count = is_break ? MAX_HW_BREAKPOINTS : MAX_HW_WATCHPOINTS;
    state = get_fake_state((uint32_t)target_tid, target_tgid);
    if (!state) {
        args->skip_origin = 1;
        args->ret = -12;
        return;
    }

    args->skip_origin = 1;
    if (request == PTRACE_SETREGSET)
        args->ret = ptrace_set_fake_regs(state, is_break, &iov, max_count);
    else
        args->ret = ptrace_get_fake_regs(state, is_break, &iov, (void __user *)data, max_count);
}

/* ============================================================
 * Public API
 * ============================================================ */

long sh_ptrace_spoof_enable(uint32_t pid)
{
    ensure_ptrace_init();

    if (spoof_pid_count >= 32) return -28;

    for (int i = 0; i < spoof_pid_count; i++) {
        if (spoof_pids[i] == pid)
            return 0;
    }

    spoof_pids[spoof_pid_count++] = pid;
    if (pid == 0)
        sh_dbg("[ptrace_spoof] enabled global test mode\n");
    else
        sh_dbg("[ptrace_spoof] enabled for pid=%d\n", pid);

    /* Install ptrace hook if not done */
    if (!ptrace_hooked) {
        hook_err_t err = fp_hook_syscalln(__NR_ptrace, 4, ptrace_hook_before, 0, 0);
        if (!err) {
            ptrace_hook_type = 1;
        } else {
            pr_err("[ptrace_spoof] failed to fp-hook ptrace: %d\n", err);
            err = inline_hook_syscalln(__NR_ptrace, 4, ptrace_hook_before, 0, 0);
            if (err) {
                pr_err("[ptrace_spoof] inline hook also failed: %d\n", err);
                spoof_pid_count--;
                return -1;
            }
            ptrace_hook_type = 2;
        }
        ptrace_hooked = 1;
        sh_dbg("[ptrace_spoof] ptrace syscall hooked type=%d\n", ptrace_hook_type);
    }

    return 0;
}

long sh_ptrace_spoof_disable(uint32_t pid)
{
    ensure_ptrace_init();

    for (int i = 0; i < spoof_pid_count; i++) {
        if (spoof_pids[i] == pid) {
            for (int j = i; j < spoof_pid_count - 1; j++)
                spoof_pids[j] = spoof_pids[j + 1];
            spoof_pid_count--;

            if (pid == 0)
                sh_dbg("[ptrace_spoof] disabled global test mode\n");
            else
                sh_dbg("[ptrace_spoof] disabled for pid=%d\n", pid);

            if (spoof_pid_count == 0 && ptrace_hooked) {
                if (ptrace_hook_type == 1)
                    fp_unhook_syscalln(__NR_ptrace, ptrace_hook_before, 0);
                else if (ptrace_hook_type == 2)
                    inline_unhook_syscalln(__NR_ptrace, ptrace_hook_before, 0);
                ptrace_hooked = 0;
                ptrace_hook_type = 0;
                sh_dbg("[ptrace_spoof] ptrace syscall unhooked\n");
            }
            return 0;
        }
    }
    return -1;
}

void sh_ptrace_spoof_cleanup(void)
{
    struct list_head *pos, *tmp;
    struct fake_bp_state *state;

    if (!ptrace_spoof_initialized)
        return;

    if (ptrace_hooked) {
        if (ptrace_hook_type == 1)
            fp_unhook_syscalln(__NR_ptrace, ptrace_hook_before, 0);
        else if (ptrace_hook_type == 2)
            inline_unhook_syscalln(__NR_ptrace, ptrace_hook_before, 0);
        ptrace_hooked = 0;
        ptrace_hook_type = 0;
    }

    for (pos = ptrace_spoof_list.next; pos != &ptrace_spoof_list; pos = tmp) {
        tmp = pos->next;
        state = (struct fake_bp_state *)((char *)pos -
                __builtin_offsetof(struct fake_bp_state, list));
        pos->prev->next = pos->next;
        pos->next->prev = pos->prev;
        kf_vfree(state);
    }

    spoof_pid_count = 0;
    sh_dbg("[ptrace_spoof] cleanup done\n");
}
