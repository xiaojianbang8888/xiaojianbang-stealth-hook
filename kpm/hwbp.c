/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook - Hardware Breakpoint Management
 *
 * Features:
 * - Per-thread HWBP registration via register_user_hw_breakpoint
 * - State-machine jump: single breakpoint monitors both entry and return
 * - Inline hook mode: redirect PC to trampoline
 * - Disable/Enable for avoiding infinite recursion
 * - New thread monitoring via wake_up_new_task hook
 *
 * ARM64 limits: max 6 execution breakpoints, 4 watchpoints per thread
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

#include "stealth_hook.h"

#ifndef INIT_LIST_HEAD
#define INIT_LIST_HEAD(ptr) do { (ptr)->next = (ptr); (ptr)->prev = (ptr); } while (0)
#endif

/* Minimal pt_regs for ARM64 */
struct sh_pt_regs {
    uint64_t regs[31];  /* x0-x30 */
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

/* Strip PAC bits from pointer (ARMv8.3+) */
#define STRIP_PAC(addr) ((uint64_t)(addr) & 0x0000FFFFFFFFFFFFul)

/* Kernel function pointers */
extern void *(*kf_vmalloc)(unsigned long size);
extern void (*kf_vfree)(const void *addr);
extern unsigned long (*kf_copy_from_user)(void *to, const void __user *from, unsigned long n);
extern struct task_struct *(*kf_find_task_by_vpid)(pid_t nr);

/* copy_from_user_nofault: safe in atomic/NMI context (HWBP handler) */
static long (*kf_copy_from_user_nofault)(void *dst, const void __user *src, unsigned long size) = 0;

#define PERF_TYPE_BREAKPOINT 5
#define HW_BREAKPOINT_X 4
#define HW_BREAKPOINT_LEN_4 4
#define SH_MAX_ERRNO 4095

struct sh_perf_event_attr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    uint32_t wakeup_events;
    uint32_t bp_type;
    uint64_t bp_addr;
    uint64_t bp_len;
    uint64_t branch_sample_type;
    uint64_t sample_regs_user;
    uint32_t sample_stack_user;
    int32_t clockid;
    uint64_t sample_regs_intr;
    uint32_t aux_watermark;
    uint16_t sample_max_stack;
    uint16_t reserved_2;
    uint32_t aux_sample_size;
    uint32_t reserved_3;
    uint64_t sig_data;
};

/* perf_event / hw_breakpoint kernel APIs (resolved dynamically) */
static void *(*kf_register_user_hw_breakpoint)(void *attr, void *triggered,
                                                void *overflow_handler, void *tsk) = 0;
static void *(*kf_perf_event_create_kernel_counter)(void *attr, int cpu, void *task,
                                                     void *callback, void *context) = 0;
static int (*kf_modify_user_hw_breakpoint)(void *bp, void *attr) = 0;
static void (*kf_unregister_hw_breakpoint)(void *bp) = 0;
static void (*kf_perf_event_release_kernel)(void *event) = 0;
static void (*kf_perf_event_enable)(void *event) = 0;
static void (*kf_perf_event_disable)(void *event) = 0;

/* HWBP node list */
static struct list_head hwbp_list_head;
static int hwbp_list_initialized = 0;
static uint32_t hwbp_handler_enter_count;
static uint32_t hwbp_handler_unmatched_count;

struct hwbp_node {
    struct list_head list;
    uint64_t target_addr;       /* original hook address */
    uint64_t orig_bp_addr;      /* saved original bp address */
    uint64_t bp_addr;           /* current bp address (may be LR for state machine) */
    uint32_t tid;
    uint32_t pid;
    uint32_t flags;
    uint64_t callback_addr;     /* user-space callback (inline mode) */
    uint64_t trampoline_addr;   /* trampoline for inline mode */
    void *bp_handle;            /* perf_event handle */
    int is_waiting_return;      /* state: waiting for function return */
    int is_disabled;            /* temporarily disabled */
    uint32_t hit_count;
    uint64_t last_pc;
    uint64_t last_x0;
    uint64_t last_x1;
    /* Extended register capture */
    uint64_t entry_args[8];     /* X0-X7 at function entry */
    uint64_t ret_x0;            /* X0 at function return */
    uint64_t entry_lr;          /* LR (X30) at entry */
    /* Memory dump: raw bytes pointed to by each register arg */
    uint32_t dump_size;         /* bytes to dump per pointer arg (0 = no dump) */
    uint8_t  mem_dump[8][128];  /* dumped bytes per arg */
    uint16_t mem_len[8];        /* actual bytes dumped (0 = not a pointer) */
    /* Skip count: skip first N hits, capture N+1 */
    uint32_t skip_count;        /* how many entry hits to skip */
    uint32_t skipped;           /* how many already skipped */
    /* Full hook: clone data for lazy init */
    void *clone_data;           /* kernel vmalloc buffer holding clone insns */
    uint32_t clone_size;        /* size in bytes */
    uint64_t ghost_va;          /* allocated ghost VA in target process (0 = not yet) */
    uint32_t tramp_offset;      /* offset of trampoline within clone data (in insn slots) */
    /* Override: modify args / skip origin */
    uint64_t override_mask;     /* bit N = override regs[N] on entry */
    uint64_t override_args[8];  /* replacement values for X0-X7 */
    uint64_t ret_value;         /* return value when SKIP_ORIGIN */
};

static void ensure_hwbp_list_init(void)
{
    if (!hwbp_list_initialized) {
        INIT_LIST_HEAD(&hwbp_list_head);
        hwbp_list_initialized = 1;
    }
}

/* Find HWBP node by current breakpoint address and TID */
static struct hwbp_node *find_hwbp_by_addr_tid(uint64_t addr, uint32_t tid)
{
    struct list_head *pos;
    struct hwbp_node *node;

    for (pos = hwbp_list_head.next; pos != &hwbp_list_head; pos = pos->next) {
        node = (struct hwbp_node *)((char *)pos -
               __builtin_offsetof(struct hwbp_node, list));
        if (node->bp_addr == addr && node->tid == tid)
            return node;
    }
    return 0;
}

static int resolve_hwbp_symbols(void)
{
    if (!kf_copy_from_user_nofault)
        kf_copy_from_user_nofault = (typeof(kf_copy_from_user_nofault))
            kallsyms_lookup_name("copy_from_user_nofault");

    if (!kf_register_user_hw_breakpoint) {
        kf_register_user_hw_breakpoint = (typeof(kf_register_user_hw_breakpoint))
            kallsyms_lookup_name("register_user_hw_breakpoint");
        kf_perf_event_create_kernel_counter = (typeof(kf_perf_event_create_kernel_counter))
            kallsyms_lookup_name("perf_event_create_kernel_counter");
        kf_modify_user_hw_breakpoint = (typeof(kf_modify_user_hw_breakpoint))
            kallsyms_lookup_name("modify_user_hw_breakpoint");
        kf_unregister_hw_breakpoint = (typeof(kf_unregister_hw_breakpoint))
            kallsyms_lookup_name("unregister_hw_breakpoint");
        kf_perf_event_release_kernel = (typeof(kf_perf_event_release_kernel))
            kallsyms_lookup_name("perf_event_release_kernel");
        kf_perf_event_enable = (typeof(kf_perf_event_enable))
            kallsyms_lookup_name("perf_event_enable");
        kf_perf_event_disable = (typeof(kf_perf_event_disable))
            kallsyms_lookup_name("perf_event_disable");
        sh_dbg("[hwbp] symbols: register=%llx kernel_counter=%llx modify=%llx unregister=%llx release=%llx enable=%llx disable=%llx\n",
                (uint64_t)kf_register_user_hw_breakpoint,
                (uint64_t)kf_perf_event_create_kernel_counter,
                (uint64_t)kf_modify_user_hw_breakpoint,
                (uint64_t)kf_unregister_hw_breakpoint,
                (uint64_t)kf_perf_event_release_kernel,
                (uint64_t)kf_perf_event_enable,
                (uint64_t)kf_perf_event_disable);
    }

    if ((!kf_register_user_hw_breakpoint && !kf_perf_event_create_kernel_counter) ||
        (!kf_unregister_hw_breakpoint && !kf_perf_event_release_kernel)) {
        pr_err("[hwbp] required register/release symbols missing\n");
        return 0;
    }

    if (!kf_modify_user_hw_breakpoint)
        sh_dbg("[hwbp] modify_user_hw_breakpoint missing, listen_ret will be unavailable\n");
    if (!kf_perf_event_enable || !kf_perf_event_disable)
        sh_dbg("[hwbp] perf enable/disable missing, lifecycle controls will be limited\n");

    return 1;
}

static void fill_execute_attr(struct sh_perf_event_attr *attr, uint64_t addr, int disabled)
{
    memset(attr, 0, sizeof(*attr));
    attr->type = PERF_TYPE_BREAKPOINT;
    attr->size = sizeof(*attr);
    attr->sample_period = 1;
    attr->bp_type = HW_BREAKPOINT_X;
    attr->bp_addr = addr;
    attr->bp_len = HW_BREAKPOINT_LEN_4;
    if (disabled)
        attr->flags = 1;
}

/*
 * Hardware breakpoint trigger callback.
 * Implements:
 * 1. Inline Hook: redirect PC to trampoline
 * 2. Observer (state machine): capture args/retval via single BP jump
 */
static void hwbp_handler(void *bp, void *sample_data, struct sh_pt_regs *regs)
{
    struct list_head *pos;
    struct hwbp_node *matched = 0;
    struct hwbp_node *single_active = 0;
    int active_count = 0;

    (void)sample_data;
    hwbp_handler_enter_count++;

    for (pos = hwbp_list_head.next; pos != &hwbp_list_head; pos = pos->next) {
        struct hwbp_node *node = (struct hwbp_node *)((char *)pos -
                                  __builtin_offsetof(struct hwbp_node, list));
        if (!node->is_disabled) {
            single_active = node;
            active_count++;
        }
        if (!matched && node->bp_handle == bp && !node->is_disabled) {
            matched = node;
            break;
        }
    }

    if ((!matched || matched->is_disabled) && active_count == 1)
        matched = single_active;

    if (!matched || matched->is_disabled) {
        hwbp_handler_unmatched_count++;
        return;
    }

    matched->hit_count++;
    matched->last_pc = regs->pc;
    matched->last_x0 = regs->regs[0];
    matched->last_x1 = regs->regs[1];

    /* Mode 0: Skip Origin - skip function entirely, return fake value */
    if (matched->flags & SH_HWBP_FLAG_SKIP_ORIGIN) {
        regs->regs[0] = matched->ret_value;
        regs->pc = STRIP_PAC(regs->regs[30]);  /* jump to LR */
        return;
    }

    /* Mode 0.5: Modify Args - overwrite selected registers, then fall through */
    if (matched->flags & SH_HWBP_FLAG_MODIFY_ARGS) {
        if (!matched->is_waiting_return) {  /* only on entry, not on return */
            for (int i = 0; i < 8; i++) {
                if (matched->override_mask & (1ULL << i))
                    regs->regs[i] = matched->override_args[i];
            }
        }
        /* Fall through to LISTEN_RET or one-shot logic below */
    }

    /* Mode 1: Inline Hook - redirect PC */
    if (matched->flags & SH_HWBP_FLAG_INLINE) {
        regs->pc = matched->trampoline_addr;
        return;
    }

    /* Mode 3: Full Hook - write trampoline on first hit, then redirect.
     * compat_copy_to_user doesn't sleep, safe in atomic context.
     * Target address must be in an already-mapped writable page (e.g. rwxp SO region). */
    if (matched->flags & SH_HWBP_FLAG_FULL_HOOK) {
        if (!matched->ghost_va && matched->clone_data && matched->clone_size && matched->trampoline_addr) {
            /* First hit: write clone data to pre-determined address in target process */
            int copied = compat_copy_to_user((void __user *)matched->trampoline_addr,
                                             matched->clone_data, matched->clone_size);
            if (copied == (int)matched->clone_size) {
                matched->ghost_va = matched->trampoline_addr; /* mark as initialized */
            }
        }
        if (matched->ghost_va) {
            regs->pc = matched->trampoline_addr + (uint64_t)matched->tramp_offset * 4;
        }
        return;
    }

    /* Mode 2: Observer - State Machine */
    if (matched->is_waiting_return) {
        struct sh_perf_event_attr attr;

        sh_dbg("[hwbp] RET addr=%llx X0=%llx\n", regs->pc, regs->regs[0]);
        matched->ret_x0 = regs->regs[0];  /* capture return value */
        matched->bp_addr = matched->orig_bp_addr;
        matched->is_waiting_return = 0;

        if (kf_modify_user_hw_breakpoint && kf_perf_event_disable && kf_perf_event_enable && matched->bp_handle) {
            fill_execute_attr(&attr, matched->bp_addr, 0);
            kf_perf_event_disable(matched->bp_handle);
            kf_modify_user_hw_breakpoint(matched->bp_handle, &attr);
            kf_perf_event_enable(matched->bp_handle);
        }
        return;
    }

    /* State A: at function entry */
    sh_dbg("[hwbp] ENTRY addr=%llx X0=%llx X1=%llx X2=%llx X3=%llx\n",
            regs->pc, regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3]);

    /* Skip count: only capture the Nth entry hit */
    if (matched->skip_count > 0 && matched->skipped < matched->skip_count) {
        matched->skipped++;
        /* Still do LISTEN_RET state machine if enabled */
        if ((matched->flags & SH_HWBP_FLAG_LISTEN_RET) && kf_modify_user_hw_breakpoint) {
            struct sh_perf_event_attr attr;
            uint64_t lr = STRIP_PAC(regs->regs[30]);
            if (lr) {
                matched->bp_addr = lr;
                matched->is_waiting_return = 1;
                fill_execute_attr(&attr, lr, 0);
                kf_perf_event_disable(matched->bp_handle);
                kf_modify_user_hw_breakpoint(matched->bp_handle, &attr);
                kf_perf_event_enable(matched->bp_handle);
            }
        }
        return;
    }

    /* Capture entry args X0-X7 and LR */
    for (int i = 0; i < 8; i++)
        matched->entry_args[i] = regs->regs[i];
    matched->entry_lr = regs->regs[30];

    /* Memory dump: for each register that looks like a user pointer,
     * dump raw bytes. No type guessing — userspace renders hex+ascii.
     * PAN must be disabled to read user memory in debug exception context. */
    if (matched->dump_size) {
        uint32_t dn = matched->dump_size > 128 ? 128 : matched->dump_size;
        asm volatile(".inst 0xd500409f" ::: "memory");  /* msr pan, #0 */
        for (int i = 0; i < 8; i++) {
            uint64_t ptr = regs->regs[i];
            if (ptr < 0x100000ULL || ptr > 0x7FFFFFFFFFFFULL) {
                matched->mem_len[i] = 0;
                continue;
            }
            for (uint32_t j = 0; j < dn; j++)
                matched->mem_dump[i][j] = *(volatile uint8_t *)(ptr + j);
            matched->mem_len[i] = (uint16_t)dn;
        }
        asm volatile(".inst 0xd500419f" ::: "memory");  /* msr pan, #1 */
    }

    /* State machine: ALWAYS jump BP to LR after entry capture.
     * This avoids infinite re-triggering on the same instruction.
     * When LR is hit (function returns), BP jumps back to orig_bp_addr.
     * LISTEN_RET flag controls whether ret_x0 is recorded on return. */
    if (kf_modify_user_hw_breakpoint) {
        struct sh_perf_event_attr attr;
        uint64_t lr = STRIP_PAC(regs->regs[30]);

        if (!lr)
            return;

        matched->bp_addr = lr;
        matched->is_waiting_return = 1;
        fill_execute_attr(&attr, lr, 0);
        kf_perf_event_disable(matched->bp_handle);
        kf_modify_user_hw_breakpoint(matched->bp_handle, &attr);
        kf_perf_event_enable(matched->bp_handle);
    } else {
        /* Fallback: modify unavailable, disable to prevent infinite loop */
        matched->is_disabled = 1;
        if (kf_perf_event_disable && matched->bp_handle)
            kf_perf_event_disable(matched->bp_handle);
    }
}

/* ============================================================
 * Public API
 * ============================================================ */

long sh_hwbp_hook(struct sh_hwbp_request __user *req)
{
    struct sh_hwbp_request kreq;
    struct hwbp_node *node;

    ensure_hwbp_list_init();

    if (!kf_copy_from_user || kf_copy_from_user(&kreq, req, sizeof(kreq)))
        return -14;

    sh_dbg("[hwbp] hook: tid=%d, addr=%llx, flags=%x\n",
            kreq.target_pid, kreq.target_addr, kreq.flags);

    if (!kreq.target_addr || !kreq.target_pid)
        return -22;
    if (!(kreq.flags & SH_HWBP_FLAG_EXECUTE))
        return -22;
    if ((kreq.flags & SH_HWBP_FLAG_LISTEN_RET) &&
        (!kf_modify_user_hw_breakpoint || !kf_perf_event_enable || !kf_perf_event_disable)) {
        if (!resolve_hwbp_symbols())
            return -95;
        if (!kf_modify_user_hw_breakpoint || !kf_perf_event_enable || !kf_perf_event_disable) {
            pr_err("[hwbp] listen_ret requires modify and perf enable/disable symbols\n");
            return -95;
        }
    } else if (!resolve_hwbp_symbols()) {
        return -95;
    }
    if (!kf_find_task_by_vpid || !kf_vmalloc)
        return -95;

    void *task = kf_find_task_by_vpid((pid_t)kreq.target_pid);
    if (!task) {
        pr_err("[hwbp] target tid not found: %d\n", kreq.target_pid);
        return -3;
    }

    node = (struct hwbp_node *)kf_vmalloc(sizeof(struct hwbp_node));
    if (!node) return -12;

    memset(node, 0, sizeof(*node));
    node->target_addr = kreq.target_addr;
    node->orig_bp_addr = kreq.target_addr;
    node->bp_addr = kreq.target_addr;
    node->tid = kreq.target_pid;
    node->pid = kreq.target_pid;
    node->flags = kreq.flags;
    node->callback_addr = kreq.callback_addr;
    node->trampoline_addr = kreq.trampoline_addr;
    node->dump_size = kreq.dump_size > 128 ? 128 : kreq.dump_size;
    node->is_disabled = 1;

    struct sh_perf_event_attr attr;
    fill_execute_attr(&attr, kreq.target_addr, (kreq.flags & SH_HWBP_FLAG_NO_AUTO_ENABLE) ? 1 : 0);
    if (kf_perf_event_create_kernel_counter)
        node->bp_handle = kf_perf_event_create_kernel_counter(&attr, -1, task, hwbp_handler, 0);
    else
        node->bp_handle = kf_register_user_hw_breakpoint(&attr, hwbp_handler, 0, task);
    if (!node->bp_handle || (uint64_t)node->bp_handle >= (uint64_t)-SH_MAX_ERRNO) {
        long err = node->bp_handle ? (long)node->bp_handle : -5;
        pr_err("[hwbp] register failed: %llx err=%ld attr_size=%u type=%u bp_type=%u bp_addr=%llx bp_len=%llx flags=%llx\n",
               (uint64_t)node->bp_handle, err, attr.size, attr.type, attr.bp_type,
               attr.bp_addr, attr.bp_len, attr.flags);
        kf_vfree(node);
        return err;
    }

    node->list.next = hwbp_list_head.next;
    node->list.prev = &hwbp_list_head;
    hwbp_list_head.next->prev = &node->list;
    hwbp_list_head.next = &node->list;

    if (kreq.flags & SH_HWBP_FLAG_NO_AUTO_ENABLE)
        node->is_disabled = 1;
    else
        node->is_disabled = 0;

    sh_dbg("[hwbp] registered: tid=%d addr=%llx handle=%llx disabled=%d\n",
            node->tid, node->target_addr, (uint64_t)node->bp_handle, node->is_disabled);
    return 0;
}

/*
 * Full hook: register HWBP + store clone data in kernel for lazy init.
 * Args: arg1 = sh_hwbp_request*, arg2 = clone_data_ptr, arg3 = clone_size, arg4 = tramp_offset
 */
long sh_hwbp_hook_full(struct sh_hwbp_request __user *req, void __user *clone_ptr,
                       uint32_t clone_size, uint32_t tramp_offset)
{
    struct sh_hwbp_request kreq;

    ensure_hwbp_list_init();

    if (!kf_copy_from_user || kf_copy_from_user(&kreq, req, sizeof(kreq)))
        return -14;

    /* Force FULL_HOOK flag */
    kreq.flags |= SH_HWBP_FLAG_FULL_HOOK | SH_HWBP_FLAG_EXECUTE;

    if (!clone_ptr || !clone_size || clone_size > 256 * 1024)
        return -22;
    if (!resolve_hwbp_symbols())
        return -95;
    if (!kf_find_task_by_vpid || !kf_vmalloc)
        return -95;

    void *task = kf_find_task_by_vpid((pid_t)kreq.target_pid);
    if (!task)
        return -3;

    /* Allocate kernel buffer and copy clone data from userspace */
    void *kbuf = kf_vmalloc(clone_size);
    if (!kbuf)
        return -12;
    if (kf_copy_from_user(kbuf, clone_ptr, clone_size)) {
        kf_vfree(kbuf);
        return -14;
    }

    /* Create node */
    struct hwbp_node *node = (struct hwbp_node *)kf_vmalloc(sizeof(struct hwbp_node));
    if (!node) { kf_vfree(kbuf); return -12; }

    memset(node, 0, sizeof(*node));
    node->target_addr = kreq.target_addr;
    node->orig_bp_addr = kreq.target_addr;
    node->bp_addr = kreq.target_addr;
    node->tid = kreq.target_pid;
    node->pid = kreq.target_pid;
    node->flags = kreq.flags;
    node->clone_data = kbuf;
    node->clone_size = clone_size;
    node->tramp_offset = tramp_offset;
    node->trampoline_addr = kreq.trampoline_addr; /* pre-computed write target in rwxp region */

    /* Register HWBP */
    struct sh_perf_event_attr attr;
    fill_execute_attr(&attr, kreq.target_addr, 0);
    if (kf_perf_event_create_kernel_counter)
        node->bp_handle = kf_perf_event_create_kernel_counter(&attr, -1, task, hwbp_handler, 0);
    else
        node->bp_handle = kf_register_user_hw_breakpoint(&attr, hwbp_handler, 0, task);

    if (!node->bp_handle || (uint64_t)node->bp_handle >= (uint64_t)-SH_MAX_ERRNO) {
        kf_vfree(kbuf);
        kf_vfree(node);
        return -5;
    }

    node->list.next = hwbp_list_head.next;
    node->list.prev = &hwbp_list_head;
    hwbp_list_head.next->prev = &node->list;
    hwbp_list_head.next = &node->list;

    return 0;
}

long sh_hwbp_unhook(uint64_t target_addr, uint32_t pid)
{
    struct list_head *pos, *tmp;
    struct hwbp_node *node;

    ensure_hwbp_list_init();

    for (pos = hwbp_list_head.next; pos != &hwbp_list_head; pos = tmp) {
        tmp = pos->next;
        node = (struct hwbp_node *)((char *)pos -
               __builtin_offsetof(struct hwbp_node, list));
        if (node->target_addr == target_addr && (pid == 0 || node->tid == pid || node->pid == pid)) {
            if (node->bp_handle) {
                if (kf_perf_event_release_kernel)
                    kf_perf_event_release_kernel(node->bp_handle);
                else if (kf_unregister_hw_breakpoint)
                    kf_unregister_hw_breakpoint(node->bp_handle);
            }
            pos->prev->next = pos->next;
            pos->next->prev = pos->prev;
            kf_vfree(node);
            return 0;
        }
    }
    return -1;
}

long sh_hwbp_enable(uint64_t target_addr, uint32_t tid)
{
    struct list_head *pos;
    struct hwbp_node *node;
    ensure_hwbp_list_init();

    for (pos = hwbp_list_head.next; pos != &hwbp_list_head; pos = pos->next) {
        node = (struct hwbp_node *)((char *)pos -
               __builtin_offsetof(struct hwbp_node, list));
        if (node->target_addr == target_addr && (tid == 0 || node->tid == tid)) {
            node->is_disabled = 0;
            if (node->bp_handle && kf_perf_event_enable)
                kf_perf_event_enable(node->bp_handle);
            return 0;
        }
    }
    return -1;
}

long sh_hwbp_disable(uint64_t target_addr, uint32_t tid)
{
    struct list_head *pos;
    struct hwbp_node *node;
    ensure_hwbp_list_init();

    for (pos = hwbp_list_head.next; pos != &hwbp_list_head; pos = pos->next) {
        node = (struct hwbp_node *)((char *)pos -
               __builtin_offsetof(struct hwbp_node, list));
        if (node->target_addr == target_addr && (tid == 0 || node->tid == tid)) {
            node->is_disabled = 1;
            if (node->bp_handle && kf_perf_event_disable)
                kf_perf_event_disable(node->bp_handle);
            return 0;
        }
    }
    return -1;
}

long sh_hwbp_query(struct sh_hwbp_query __user *req)
{
    struct sh_hwbp_query kreq;
    struct list_head *pos;
    struct hwbp_node *node;
    int copied;
    uint32_t match_idx = 0;
    uint32_t total = 0;
    struct hwbp_node *chosen = 0;

    ensure_hwbp_list_init();

    if (!kf_copy_from_user || kf_copy_from_user(&kreq, req, sizeof(kreq)))
        return -14;

    /* Two-pass: count all nodes matching target_addr (and optional tid),
     * and pick the one at kreq.node_index. This lets userspace enumerate
     * every per-thread node (each thread has its own HWBP node). */
    for (pos = hwbp_list_head.next; pos != &hwbp_list_head; pos = pos->next) {
        node = (struct hwbp_node *)((char *)pos -
               __builtin_offsetof(struct hwbp_node, list));
        if (node->target_addr == kreq.target_addr && (kreq.tid == 0 || node->tid == kreq.tid)) {
            if (total == kreq.node_index)
                chosen = node;
            total++;
        }
        (void)match_idx;
    }

    kreq.node_total = total;

    if (!chosen) {
        /* node_index out of range, but still report total so caller can stop */
        kreq.hit_count = 0;
        kreq.tid = 0;
        copied = compat_copy_to_user(req, &kreq, sizeof(kreq));
        return total > 0 ? 0 : -2;
    }

    node = chosen;
    kreq.tid = node->tid;
    kreq.hit_count = node->hit_count;
    kreq.last_pc = node->last_pc;
    kreq.last_x0 = node->last_x0;
    kreq.last_x1 = node->last_x1;
    kreq.is_disabled = node->is_disabled;
    kreq.is_waiting_return = node->is_waiting_return;
    kreq.handler_enter_count = hwbp_handler_enter_count;
    kreq.handler_unmatched_count = hwbp_handler_unmatched_count;
    for (int i = 0; i < 8; i++)
        kreq.entry_args[i] = node->entry_args[i];
    kreq.ret_x0 = node->ret_x0;
    kreq.entry_lr = node->entry_lr;
    /* Copy memory dumps */
    for (int i = 0; i < 8; i++) {
        kreq.mem_len[i] = node->mem_len[i];
        if (node->mem_len[i])
            memcpy(kreq.mem_dump[i], node->mem_dump[i], node->mem_len[i]);
    }

    copied = compat_copy_to_user(req, &kreq, sizeof(kreq));
    if (copied != (int)sizeof(kreq))
        return -14;
    return 0;
}

/*
 * Set override config on existing HWBP node(s).
 * Also updates flags to include MODIFY_ARGS / SKIP_ORIGIN as specified.
 */
long sh_hwbp_set_override(struct sh_hwbp_override __user *req)
{
    struct sh_hwbp_override kov;
    struct list_head *pos;
    struct hwbp_node *node;
    int found = 0;

    ensure_hwbp_list_init();

    if (!kf_copy_from_user || kf_copy_from_user(&kov, req, sizeof(kov)))
        return -14;

    for (pos = hwbp_list_head.next; pos != &hwbp_list_head; pos = pos->next) {
        node = (struct hwbp_node *)((char *)pos -
               __builtin_offsetof(struct hwbp_node, list));
        if (node->target_addr == kov.target_addr &&
            (kov.target_pid == 0 || node->tid == kov.target_pid || node->pid == kov.target_pid)) {
            node->override_mask = kov.override_mask;
            for (int i = 0; i < 8; i++)
                node->override_args[i] = kov.override_args[i];
            node->ret_value = kov.ret_value;
            /* Use explicit flags from userspace */
            if (kov.flags & SH_HWBP_FLAG_MODIFY_ARGS)
                node->flags |= SH_HWBP_FLAG_MODIFY_ARGS;
            if (kov.flags & SH_HWBP_FLAG_SKIP_ORIGIN)
                node->flags |= SH_HWBP_FLAG_SKIP_ORIGIN;
            found++;
        }
    }

    return found > 0 ? 0 : -2;
}

/* sh_hwbp_set_arg_type / sh_hwbp_read_str removed:
 * string capture replaced by generic memory dump (node->mem_dump),
 * returned directly in sh_hwbp_query. */

/*
 * Set skip count: capture the Nth entry hit (skip first N-1).
 * arg1 = target_addr, arg2 = skip_count (0 = capture first hit)
 */
long sh_hwbp_set_skip(uint64_t target_addr, uint32_t skip_count)
{
    struct list_head *pos;
    struct hwbp_node *node;
    int found = 0;

    ensure_hwbp_list_init();

    for (pos = hwbp_list_head.next; pos != &hwbp_list_head; pos = pos->next) {
        node = (struct hwbp_node *)((char *)pos -
               __builtin_offsetof(struct hwbp_node, list));
        if (node->target_addr == target_addr) {
            node->skip_count = skip_count;
            node->skipped = 0;
            node->hit_count = 0;  /* reset hit count */
            found++;
        }
    }
    return found > 0 ? 0 : -2;
}

void sh_hwbp_cleanup(void)
{
    struct list_head *pos, *tmp;
    struct hwbp_node *node;

    if (!hwbp_list_initialized)
        return;

    for (pos = hwbp_list_head.next; pos != &hwbp_list_head; pos = tmp) {
        tmp = pos->next;
        node = (struct hwbp_node *)((char *)pos -
               __builtin_offsetof(struct hwbp_node, list));
        if (node->bp_handle && kf_unregister_hw_breakpoint)
            kf_unregister_hw_breakpoint(node->bp_handle);
        pos->prev->next = pos->next;
        pos->next->prev = pos->prev;
        kf_vfree(node);
    }
}

/* ============================================================
 * Auto-thread: register HWBP on new threads of target TGID
 * Uses hook_wrap on wake_up_new_task(struct task_struct *p)
 * ============================================================ */

#define SH_AUTO_THREAD_MAX 4

struct auto_thread_rule {
    uint64_t target_addr;
    uint64_t trampoline_addr;
    uint32_t tgid;
    uint32_t flags;
};

static struct auto_thread_rule auto_rules[SH_AUTO_THREAD_MAX];
static int auto_rule_count = 0;
static void *wake_up_fn = 0;
static int wake_up_hooked = 0;

/* PID helpers */
static pid_t (*kf_task_tgid_nr)(void *task) = 0;

static void wake_up_new_task_after(hook_fargs1_t *args, void *udata)
{
    (void)udata;
    void *new_task = (void *)args->arg0;
    if (!new_task || !auto_rule_count)
        return;

    if (!kf_task_tgid_nr)
        kf_task_tgid_nr = (typeof(kf_task_tgid_nr))kallsyms_lookup_name("task_tgid_nr");
    if (!kf_task_tgid_nr)
        return;

    uint32_t new_tgid = (uint32_t)kf_task_tgid_nr(new_task);

    for (int i = 0; i < auto_rule_count; i++) {
        if (auto_rules[i].tgid != new_tgid)
            continue;

        /* Register HWBP on the new thread */
        struct sh_perf_event_attr attr;
        fill_execute_attr(&attr, auto_rules[i].target_addr, 0);

        void *bp = 0;
        if (kf_perf_event_create_kernel_counter)
            bp = kf_perf_event_create_kernel_counter(&attr, -1, new_task, hwbp_handler, 0);
        else if (kf_register_user_hw_breakpoint)
            bp = kf_register_user_hw_breakpoint(&attr, hwbp_handler, 0, new_task);

        if (!bp || (uint64_t)bp >= (uint64_t)-SH_MAX_ERRNO)
            continue;

        if (!kf_vmalloc) continue;
        struct hwbp_node *node = (struct hwbp_node *)kf_vmalloc(sizeof(struct hwbp_node));
        if (!node) { kf_unregister_hw_breakpoint(bp); continue; }

        memset(node, 0, sizeof(*node));
        node->target_addr = auto_rules[i].target_addr;
        node->orig_bp_addr = auto_rules[i].target_addr;
        node->bp_addr = auto_rules[i].target_addr;
        node->flags = auto_rules[i].flags;
        node->trampoline_addr = auto_rules[i].trampoline_addr;
        node->bp_handle = bp;

        node->list.next = hwbp_list_head.next;
        node->list.prev = &hwbp_list_head;
        hwbp_list_head.next->prev = &node->list;
        hwbp_list_head.next = &node->list;
    }
}

long sh_hwbp_auto_thread(uint64_t target_addr, uint32_t tgid,
                         uint64_t trampoline_addr, uint32_t flags)
{
    ensure_hwbp_list_init();
    if (!resolve_hwbp_symbols())
        return -95;

    if (auto_rule_count >= SH_AUTO_THREAD_MAX)
        return -28; /* ENOSPC */

    /* Install wake_up_new_task hook if not already */
    if (!wake_up_hooked) {
        wake_up_fn = (void *)kallsyms_lookup_name("wake_up_new_task");
        if (!wake_up_fn)
            return -2;
        hook_err_t e = hook_wrap1(wake_up_fn, 0, wake_up_new_task_after, 0);
        if (e)
            return -1;
        wake_up_hooked = 1;
    }

    auto_rules[auto_rule_count].target_addr = target_addr;
    auto_rules[auto_rule_count].tgid = tgid;
    auto_rules[auto_rule_count].trampoline_addr = trampoline_addr;
    auto_rules[auto_rule_count].flags = flags;
    auto_rule_count++;

    return 0;
}

void sh_hwbp_auto_thread_cleanup(void)
{
    if (wake_up_hooked && wake_up_fn) {
        hook_unwrap(wake_up_fn, 0, wake_up_new_task_after);
        wake_up_hooked = 0;
    }
    auto_rule_count = 0;
}
