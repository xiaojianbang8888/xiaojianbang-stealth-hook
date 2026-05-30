/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook Framework - Common Definitions
 * Based on KernelPatch Module (KPM)
 */

#ifndef _STEALTH_HOOK_H_
#define _STEALTH_HOOK_H_

#include <ktypes.h>

/* Debug logging: compile with -DSH_DEBUG to enable */
#ifdef SH_DEBUG
#define sh_dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
#define sh_dbg(fmt, ...) do {} while(0)
#endif

/* ============================================================
 * Syscall Bridge Commands
 * User-space communicates with KPM via hooked syscall #285.
 * Syscall #45 is reserved by KernelPatch supercall.
 * ============================================================ */

#define SH_SYSCALL_MAGIC    0x584A42   /* "XJB" */

#define SH_CMD_STATUS              0x0001
#define SH_STATUS_MAGIC            0x53484F4B  /* "SHOK" */
#define SH_VERSION_CODE            0x00010000

/* HWBP commands */
#define SH_CMD_HWBP_HOOK           0x1001
#define SH_CMD_HWBP_UNHOOK         0x1002
#define SH_CMD_HWBP_ENABLE         0x1003
#define SH_CMD_HWBP_DISABLE        0x1004
#define SH_CMD_HWBP_SET_CALLBACK   0x1005
#define SH_CMD_HWBP_QUERY          0x1006
#define SH_CMD_HWBP_AUTO_THREAD    0x1007  /* auto-register HWBP on new threads of target TGID */
#define SH_CMD_HWBP_HOOK_FULL     0x1008  /* full hook: HWBP + clone data for lazy init */
#define SH_CMD_HWBP_SET_OVERRIDE  0x1009  /* set override: modify args / skip origin */
#define SH_CMD_HWBP_SET_ARG_TYPE  0x100A  /* DEPRECATED (replaced by mem dump) */
#define SH_CMD_HWBP_READ_STR      0x100B  /* DEPRECATED (replaced by mem dump in query) */
#define SH_CMD_HWBP_SET_SKIP     0x100C  /* set skip count: capture Nth hit */

/* PTE Hook commands */
#define SH_CMD_PTE_HOOK            0x2001
#define SH_CMD_PTE_UNHOOK          0x2002
#define SH_CMD_PTE_COMMIT_DBI      0x2003
#define SH_CMD_PTE_REARM           0x2004

/* Ghost Memory commands */
#define SH_CMD_GHOST_ALLOC         0x3001
#define SH_CMD_GHOST_FREE          0x3002
#define SH_CMD_GHOST_WRITE         0x3003

/* Maps Hide commands */
#define SH_CMD_MAPS_HIDE_ADD       0x4001
#define SH_CMD_MAPS_HIDE_REMOVE    0x4002

/* Ptrace Spoof commands */
#define SH_CMD_PTRACE_SPOOF_ENABLE  0x5001
#define SH_CMD_PTRACE_SPOOF_DISABLE 0x5002

/* ============================================================
 * Shared Structures (user-space <-> kernel)
 * ============================================================ */

#define SH_MAX_HWBP_PER_THREAD  6
#define SH_MAX_WATCHPOINTS      4
#define SH_PAGE_SIZE            4096
#define SH_INSN_PER_PAGE        (SH_PAGE_SIZE / 4)

/* HWBP hook request */
struct sh_hwbp_request {
    uint64_t target_addr;       /* address to hook */
    uint32_t target_pid;        /* target process (TGID) */
    uint32_t flags;             /* SH_HWBP_FLAG_* */
    uint64_t callback_addr;     /* user-space callback (for inline mode) */
    uint64_t trampoline_addr;   /* trampoline address */
    uint32_t dump_size;         /* bytes to dump per pointer arg (0 = no dump) */
    uint32_t _pad;
};

#define SH_DUMP_MAX  128        /* max bytes dumped per register pointer */

struct sh_hwbp_query {
    uint64_t target_addr;
    uint32_t tid;
    uint32_t hit_count;
    uint64_t last_pc;
    uint64_t last_x0;
    uint64_t last_x1;
    uint32_t is_disabled;
    uint32_t is_waiting_return;
    uint32_t handler_enter_count;
    uint32_t handler_unmatched_count;
    /* Extended: full register capture */
    uint64_t entry_args[8];     /* X0-X7 at function entry */
    uint64_t ret_x0;            /* X0 at function return */
    uint64_t entry_lr;          /* LR at entry (X30) */
    /* Memory dump: raw bytes pointed to by each register arg */
    uint8_t  mem_dump[8][SH_DUMP_MAX];  /* dumped bytes per arg */
    uint16_t mem_len[8];        /* actual bytes dumped (0 = not a pointer / no dump) */
    /* Iteration cursor: query the Nth matching node (for per-thread enumeration) */
    uint32_t node_index;        /* in: which matching node to return (0-based) */
    uint32_t node_total;        /* out: total matching nodes for this target_addr */
};

/* HWBP override request: modify args or skip origin */
struct sh_hwbp_override {
    uint64_t target_addr;       /* which HWBP to configure */
    uint32_t target_pid;        /* 0 = match any */
    uint32_t flags;             /* SH_HWBP_FLAG_MODIFY_ARGS / SKIP_ORIGIN to set */
    uint64_t override_mask;     /* bit N = override regs[N] */
    uint64_t override_args[8];  /* new values for X0-X7 */
    uint64_t ret_value;         /* return value when skip_origin */
};

#define SH_HWBP_FLAG_EXECUTE    (1 << 0)
#define SH_HWBP_FLAG_READ       (1 << 1)
#define SH_HWBP_FLAG_WRITE      (1 << 2)
#define SH_HWBP_FLAG_LISTEN_RET (1 << 3)  /* state-machine: also capture return value */
#define SH_HWBP_FLAG_INLINE     (1 << 4)  /* inline hook mode (redirect PC) */
#define SH_HWBP_FLAG_NO_AUTO_ENABLE (1 << 5)
#define SH_HWBP_FLAG_FULL_HOOK  (1 << 6)  /* full hook: lazy init clone page on first hit */
#define SH_HWBP_FLAG_MODIFY_ARGS (1 << 7) /* modify X0-X7 on entry */
#define SH_HWBP_FLAG_SKIP_ORIGIN (1 << 8) /* skip function: pc=LR, x0=ret_value */

/* PTE hook request */
struct sh_pte_request {
    uint64_t orig_page_addr;    /* original page address (page-aligned) */
    uint64_t recomp_page_addr;  /* recompiled page address (DBI output) */
    uint32_t target_pid;
    uint32_t offset_map[SH_INSN_PER_PAGE]; /* instruction offset mapping */
};

/* Ghost memory request */
struct sh_ghost_request {
    uint64_t target_va;         /* desired virtual address (0 = auto) */
    uint64_t size;              /* size in bytes (page-aligned) */
    uint32_t target_pid;
    uint32_t prot;              /* protection flags: R/W/X */
};

#define SH_PROT_READ    (1 << 0)
#define SH_PROT_WRITE   (1 << 1)
#define SH_PROT_EXEC    (1 << 2)

/* Ghost memory write request */
struct sh_ghost_write_request {
    uint64_t target_va;         /* ghost memory virtual address */
    uint64_t src_data;          /* user-space source buffer */
    uint64_t size;
    uint32_t target_pid;
};

/* Maps hide request */
struct sh_maps_hide_request {
    uint64_t addr_start;
    uint64_t addr_end;
    uint32_t target_pid;
    char name[64];              /* optional: hide by name pattern */
};

/* HWBP event (kernel -> user via shared ring buffer) */
struct sh_hwbp_event {
    uint64_t timestamp;
    uint64_t target_addr;
    uint32_t tid;
    uint32_t event_type;        /* 0=entry, 1=return */
    uint64_t regs[8];           /* X0-X7 (args or return value) */
    uint64_t lr;                /* link register */
    uint64_t sp;
};

#define SH_EVENT_ENTRY   0
#define SH_EVENT_RETURN  1

/* ============================================================
 * Internal kernel structures (not exposed to user-space)
 * ============================================================ */

#ifdef __KERNEL__

#include <linux/list.h>

/* Per-thread HWBP state */
struct sh_hwbp_node {
    struct list_head list;
    uint64_t target_addr;
    uint64_t orig_bp_addr;      /* original breakpoint address */
    uint64_t bp_addr;           /* current breakpoint address (may jump to LR) */
    uint32_t tid;
    uint32_t pid;
    uint32_t flags;
    uint64_t callback_addr;
    uint64_t trampoline_addr;
    void *bp_handle;            /* perf_event handle */
    int is_waiting_return;      /* state machine: waiting for return */
    int is_disabled;            /* temporarily disabled */
};

/* Per-process PTE hook state */
struct sh_pte_node {
    struct list_head list;
    uint64_t orig_page_addr;
    uint64_t recomp_page_addr;
    uint32_t pid;
    uint32_t offset_map[SH_INSN_PER_PAGE];
    uint64_t orig_pte_val;      /* saved original PTE value */
};

/* Ghost memory allocation record */
struct sh_ghost_node {
    struct list_head list;
    uint64_t user_va;           /* virtual address in target process */
    uint64_t kernel_va;         /* kernel vmalloc address */
    uint64_t size;
    uint32_t pid;
};

/* Maps hide entry */
struct sh_maps_hide_node {
    struct list_head list;
    uint64_t addr_start;
    uint64_t addr_end;
    uint32_t pid;
    char name[64];
};

/* Fake ptrace register state (per-thread) */
struct sh_ptrace_fake_regs {
    struct list_head list;
    uint32_t tid;
    uint32_t pid;
    int hw_break_count;
    int hw_watch_count;
    struct {
        uint64_t addr;
        uint32_t ctrl;
    } break_regs[SH_MAX_HWBP_PER_THREAD];
    struct {
        uint64_t addr;
        uint32_t ctrl;
    } watch_regs[SH_MAX_WATCHPOINTS];
};

#endif /* __KERNEL__ */

#endif /* _STEALTH_HOOK_H_ */
