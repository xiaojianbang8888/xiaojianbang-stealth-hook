/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook Framework - Main KPM Module
 * Syscall bridge + command dispatch
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>
#include <hook.h>
#include <pgtable.h>

#include "stealth_hook.h"

/* list_head helpers (not provided by KP headers) */
#ifndef INIT_LIST_HEAD
#define INIT_LIST_HEAD(ptr) do { (ptr)->next = (ptr); (ptr)->prev = (ptr); } while (0)
#endif

/* syscall number: use __NR3264_truncate (45) directly */
#ifndef __NR_truncate
#define __NR_truncate 45
#endif

/* Use syscall 285 (copy_file_range, 6 args) as our channel
 * #45 is taken by KernelPatch supercall
 * #46 (ftruncate, 2 args) discards args beyond the 2nd */
#define SH_SYSCALL_NR 285

KPM_NAME("xiaojianbang-stealth-hook");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("xiaojianbang");
KPM_DESCRIPTION("WeChat:xiaojianbang8888 HWBP+PTE+Ghost+MapsHide+PtraceSpoof");

/* ============================================================
 * Kernel symbol resolution
 * ============================================================ */

enum pid_type {
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

struct pid_namespace;

static pid_t (*kf_task_pid_nr_ns)(struct task_struct *task, enum pid_type type,
                                   struct pid_namespace *ns) = 0;
struct task_struct *(*kf_find_task_by_vpid)(pid_t nr) = 0;
void *(*kf_vmalloc)(unsigned long size) = 0;
void (*kf_vfree)(const void *addr) = 0;
unsigned long (*kf_vmalloc_to_pfn)(const void *addr) = 0;
void *(*kf_get_task_mm)(struct task_struct *task) = 0;
void (*kf_mmput)(void *mm) = 0;
unsigned long (*kf_copy_from_user)(void *to, const void __user *from, unsigned long n) = 0;
uint64_t *kf_pgd_va_ptr = 0;  /* pointer to pgd_va variable in KP */
uint64_t *(*kf_pgtable_entry)(uint64_t pgd, uint64_t va) = 0;
uint64_t *kf_swapper_pg_dir = 0;  /* kernel swapper_pg_dir */
int (*kf_apply_to_page_range)(void *mm, unsigned long addr, unsigned long size,
                              int (*fn)(void *, unsigned long, void *), void *data) = 0;

/* Global lists */
static struct list_head hwbp_list;
static struct list_head pte_list;
static struct list_head ghost_list;
static struct list_head maps_hide_list;
static struct list_head ptrace_fake_list;

/* ============================================================
 * Forward declarations (implemented in other .c files)
 * ============================================================ */

/* hwbp.c */
extern long sh_hwbp_hook(struct sh_hwbp_request __user *req);
extern long sh_hwbp_unhook(uint64_t target_addr, uint32_t pid);
extern long sh_hwbp_enable(uint64_t target_addr, uint32_t tid);
extern long sh_hwbp_disable(uint64_t target_addr, uint32_t tid);
extern long sh_hwbp_query(struct sh_hwbp_query __user *req);
extern long sh_hwbp_auto_thread(uint64_t target_addr, uint32_t tgid,
                                uint64_t trampoline_addr, uint32_t flags);
extern long sh_hwbp_hook_full(struct sh_hwbp_request __user *req, void __user *clone_ptr,
                              uint32_t clone_size, uint32_t tramp_offset);
extern long sh_hwbp_set_override(struct sh_hwbp_override __user *req);
extern long sh_hwbp_set_skip(uint64_t target_addr, uint32_t skip_count);
extern void sh_hwbp_cleanup(void);
extern void sh_hwbp_auto_thread_cleanup(void);

/* pte_hook.c */
extern long sh_pte_hook(struct sh_pte_request __user *req);
extern long sh_pte_unhook(uint64_t page_addr, uint32_t pid);
extern long sh_pte_commit_dbi(struct sh_pte_request __user *req);
extern long sh_pte_rearm(uint64_t page_addr, uint32_t pid);
extern void sh_pte_cleanup(void);
extern void sh_pte_unhook_fault(void);

/* ghost_mem.c */
extern long sh_ghost_alloc_direct(uint64_t va, uint64_t size, uint32_t pid, uint32_t prot);
extern long sh_ghost_alloc(struct sh_ghost_request __user *req);
extern long sh_ghost_free(uint64_t va, uint32_t pid);
extern long sh_ghost_write(struct sh_ghost_write_request __user *req);
extern void sh_ghost_cleanup(void);

/* maps_hide.c */
extern long sh_maps_hide_add(struct sh_maps_hide_request __user *req);
extern long sh_maps_hide_remove(uint64_t addr, uint32_t pid);
extern void sh_maps_hide_cleanup(void);

/* ptrace_spoof.c */
extern long sh_ptrace_spoof_enable(uint32_t pid);
extern long sh_ptrace_spoof_disable(uint32_t pid);
extern void sh_ptrace_spoof_cleanup(void);

/* ============================================================
 * Syscall Bridge: intercept syscall #285 (copy_file_range)
 * ============================================================ */

static long sh_dispatch(long cmd, long arg1, long arg2, long arg3, long arg4)
{
    switch (cmd) {
    case SH_CMD_STATUS:
        return (long)SH_STATUS_MAGIC + SH_VERSION_CODE;

    /* HWBP */
    case SH_CMD_HWBP_HOOK:
        return sh_hwbp_hook((struct sh_hwbp_request __user *)arg1);
    case SH_CMD_HWBP_UNHOOK:
        return sh_hwbp_unhook((uint64_t)arg1, (uint32_t)arg2);
    case SH_CMD_HWBP_ENABLE:
        return sh_hwbp_enable((uint64_t)arg1, (uint32_t)arg2);
    case SH_CMD_HWBP_DISABLE:
        return sh_hwbp_disable((uint64_t)arg1, (uint32_t)arg2);
    case SH_CMD_HWBP_QUERY:
        return sh_hwbp_query((struct sh_hwbp_query __user *)arg1);
    case SH_CMD_HWBP_AUTO_THREAD:
        return sh_hwbp_auto_thread((uint64_t)arg1, (uint32_t)arg2, (uint64_t)arg3, (uint32_t)arg4);
    case SH_CMD_HWBP_HOOK_FULL:
        return sh_hwbp_hook_full((struct sh_hwbp_request __user *)arg1,
                                 (void __user *)arg2, (uint32_t)arg3, (uint32_t)arg4);
    case SH_CMD_HWBP_SET_OVERRIDE:
        return sh_hwbp_set_override((struct sh_hwbp_override __user *)arg1);
    case SH_CMD_HWBP_SET_SKIP:
        return sh_hwbp_set_skip((uint64_t)arg1, (uint32_t)arg2);

    /* PTE Hook */
    case SH_CMD_PTE_HOOK:
        return sh_pte_hook((struct sh_pte_request __user *)arg1);
    case SH_CMD_PTE_UNHOOK:
        return sh_pte_unhook((uint64_t)arg1, (uint32_t)arg2);
    case SH_CMD_PTE_COMMIT_DBI:
        return sh_pte_commit_dbi((struct sh_pte_request __user *)arg1);
    case SH_CMD_PTE_REARM:
        return sh_pte_rearm((uint64_t)arg1, (uint32_t)arg2);

    /* Ghost Memory - direct args: arg1=va, arg2=size, arg3=pid, arg4=prot */
    case SH_CMD_GHOST_ALLOC:
        return sh_ghost_alloc_direct((uint64_t)arg1, (uint64_t)arg2, (uint32_t)arg3, (uint32_t)arg4);
    case SH_CMD_GHOST_FREE:
        return sh_ghost_free((uint64_t)arg1, (uint32_t)arg2);
    case SH_CMD_GHOST_WRITE:
        return sh_ghost_write((struct sh_ghost_write_request __user *)arg1);

    /* Maps Hide */
    case SH_CMD_MAPS_HIDE_ADD:
        return sh_maps_hide_add((struct sh_maps_hide_request __user *)arg1);
    case SH_CMD_MAPS_HIDE_REMOVE:
        return sh_maps_hide_remove((uint64_t)arg1, (uint32_t)arg2);

    /* Ptrace Spoof */
    case SH_CMD_PTRACE_SPOOF_ENABLE:
        return sh_ptrace_spoof_enable((uint32_t)arg1);
    case SH_CMD_PTRACE_SPOOF_DISABLE:
        return sh_ptrace_spoof_disable((uint32_t)arg1);

    default:
        return -1;
    }
}

/* Syscall hook: intercept syscall #285 as our custom channel */
static void sh_syscall_before(hook_fargs6_t *args, void *udata)
{
    long magic = (long)syscall_argn(args, 0);
    if (magic != SH_SYSCALL_MAGIC) return;

    long cmd  = (long)syscall_argn(args, 1);
    long arg1 = (long)syscall_argn(args, 2);
    long arg2 = (long)syscall_argn(args, 3);
    long arg3 = (long)syscall_argn(args, 4);
    long arg4 = (long)syscall_argn(args, 5);

    sh_dbg("[stealth-hook] dispatch cmd=0x%lx arg1=0x%lx arg2=0x%lx arg3=0x%lx arg4=0x%lx\n",
            cmd, arg1, arg2, arg3, arg4);

    /* Skip original syscall, return our result */
    args->skip_origin = 1;
    args->ret = sh_dispatch(cmd, arg1, arg2, arg3, arg4);
}

/* TODO: placeholder implementations for initial compilation */

/* ============================================================
 * Module Init / Exit
 * ============================================================ */

static void resolve_kernel_symbols(void)
{
    kf_task_pid_nr_ns = (typeof(kf_task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    kf_find_task_by_vpid = (typeof(kf_find_task_by_vpid))kallsyms_lookup_name("find_task_by_vpid");
    kf_vmalloc = (typeof(kf_vmalloc))kallsyms_lookup_name("vmalloc");
    kf_vfree = (typeof(kf_vfree))kallsyms_lookup_name("vfree");
    kf_vmalloc_to_pfn = (typeof(kf_vmalloc_to_pfn))kallsyms_lookup_name("vmalloc_to_pfn");
    kf_get_task_mm = (typeof(kf_get_task_mm))kallsyms_lookup_name("get_task_mm");
    kf_mmput = (typeof(kf_mmput))kallsyms_lookup_name("mmput");
    kf_copy_from_user = (typeof(kf_copy_from_user))kallsyms_lookup_name("__arch_copy_from_user");
    kf_pgd_va_ptr = (uint64_t *)kallsyms_lookup_name("pgd_va");
    kf_pgtable_entry = (typeof(kf_pgtable_entry))kallsyms_lookup_name("pgtable_entry");
    kf_swapper_pg_dir = (uint64_t *)kallsyms_lookup_name("swapper_pg_dir");
    kf_apply_to_page_range = (typeof(kf_apply_to_page_range))kallsyms_lookup_name("apply_to_page_range");

    /* If KP's pgd_va not available, use swapper_pg_dir as fallback */
    if (!kf_pgd_va_ptr && kf_swapper_pg_dir) {
        kf_pgd_va_ptr = kf_swapper_pg_dir;
        sh_dbg("[stealth-hook] using swapper_pg_dir as pgd_va fallback\n");
    }

    sh_dbg("[stealth-hook] vmalloc=%llx copy_from_user=%llx\n",
            (uint64_t)kf_vmalloc, (uint64_t)kf_copy_from_user);
    sh_dbg("[stealth-hook] pgd_va_ptr=%llx pgtable_entry=%llx swapper_pg_dir=%llx\n",
            (uint64_t)kf_pgd_va_ptr, (uint64_t)kf_pgtable_entry, (uint64_t)kf_swapper_pg_dir);
    sh_dbg("[stealth-hook] apply_to_page_range=%llx\n", (uint64_t)kf_apply_to_page_range);
}

static long stealth_hook_init(const char *args, const char *event, void *__user reserved)
{
    sh_dbg("[stealth-hook] init, args: %s\n", args ? args : "(null)");

    /* Initialize lists */
    INIT_LIST_HEAD(&hwbp_list);
    INIT_LIST_HEAD(&pte_list);
    INIT_LIST_HEAD(&ghost_list);
    INIT_LIST_HEAD(&maps_hide_list);
    INIT_LIST_HEAD(&ptrace_fake_list);

    /* Resolve kernel symbols */
    resolve_kernel_symbols();

    hook_err_t err = inline_hook_syscalln(SH_SYSCALL_NR, 6, sh_syscall_before, 0, 0);
    if (err) {
        pr_err("[stealth-hook] failed to hook syscall #%d, err: %d\n", SH_SYSCALL_NR, err);
        return -1;
    }

    sh_dbg("[stealth-hook] syscall bridge on #%d ready\n", SH_SYSCALL_NR);

    /* PTE Hook: do_mem_abort hook is installed lazily inside pte_hook.c
     * on first SH_CMD_PTE_HOOK command (avoids boot-time panic). */

    return 0;
}

static long stealth_hook_control(const char *args, char *__user out_msg, int outlen)
{
    sh_dbg("[stealth-hook] control, args: %s\n", args ? args : "(null)");

    if (out_msg && outlen > 0) {
        const char *status = "stealth-hook active";
        compat_copy_to_user(out_msg, status, 20);
    }
    return 0;
}

static long stealth_hook_exit(void *__user reserved)
{
    sh_dbg("[stealth-hook] exit, cleaning up...\n");

    sh_hwbp_cleanup();
    sh_hwbp_auto_thread_cleanup();
    sh_ptrace_spoof_cleanup();
    sh_pte_cleanup();
    sh_pte_unhook_fault();
    sh_ghost_cleanup();
    sh_maps_hide_cleanup();

    inline_unhook_syscalln(SH_SYSCALL_NR, sh_syscall_before, 0);

    sh_dbg("[stealth-hook] cleanup done\n");
    return 0;
}

KPM_INIT(stealth_hook_init);
KPM_CTL0(stealth_hook_control);
KPM_EXIT(stealth_hook_exit);
