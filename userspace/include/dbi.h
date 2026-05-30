/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook - DBI (Dynamic Binary Instrumentation) Engine
 * User-space ARM64 instruction recompiler
 *
 * Recompiles a page of ARM64 instructions to a clone page,
 * fixing all PC-relative addressing so the code works at the new location.
 */

#ifndef _SH_DBI_H_
#define _SH_DBI_H_

#include <stdint.h>
#include <stddef.h>

/* Page constants */
#define DBI_PAGE_SIZE       4096
#define DBI_INSN_PER_PAGE   (DBI_PAGE_SIZE / 4)
#define DBI_CLONE_MAX_SIZE  (DBI_PAGE_SIZE * 8)  /* clone page can be up to 8x larger */
#define DBI_CLONE_MAX_INSNS (DBI_CLONE_MAX_SIZE / 4)

/* Instruction classification */
typedef enum {
    INSN_NORMAL = 0,        /* No PC-relative, copy as-is */
    INSN_B,                 /* B (unconditional branch) */
    INSN_BL,                /* BL (branch with link) */
    INSN_BCOND,             /* B.cond (conditional branch) */
    INSN_CBZ,               /* CBZ/CBNZ */
    INSN_TBZ,               /* TBZ/TBNZ */
    INSN_ADRP,             /* ADRP (PC-relative page address) */
    INSN_ADR,               /* ADR (PC-relative address) */
    INSN_LDR_LIT,          /* LDR (literal, PC-relative load) */
    INSN_BLR,               /* BLR/BLRAA/BLRAB (branch to register with link) */
    INSN_RET,               /* RET */
} dbi_insn_type_t;

/* Decoded instruction info */
typedef struct {
    uint32_t raw;           /* raw instruction bits */
    dbi_insn_type_t type;   /* classification */
    int64_t imm;            /* immediate/offset value */
    uint32_t rd;            /* destination register */
    uint32_t rn;            /* source register (for CBZ/TBZ) */
    uint32_t cond;          /* condition code (for B.cond) */
    int is_link;            /* BL vs B, CBNZ vs CBZ, TBNZ vs TBZ */
    int bit_pos;            /* bit position for TBZ/TBNZ */
} dbi_decoded_t;

/* Recompilation result for one page */
typedef struct {
    uint32_t clone_insns[DBI_CLONE_MAX_INSNS]; /* recompiled instructions */
    uint32_t clone_count;                       /* number of instructions in clone */
    uint32_t offset_map[DBI_INSN_PER_PAGE];    /* orig_idx -> clone_offset */
} dbi_result_t;

/* ============================================================
 * Public API
 * ============================================================ */

/**
 * Decode a single ARM64 instruction.
 * @param insn      Raw 32-bit instruction
 * @param pc        Virtual address where this instruction lives
 * @param out       Decoded result
 */
void dbi_decode(uint32_t insn, uint64_t pc, dbi_decoded_t *out);

/**
 * Recompile a page of instructions.
 * @param orig_insns    Pointer to original instructions (1024 insns = 4KB page)
 * @param orig_page_va  Virtual address of the original page
 * @param clone_page_va Virtual address where clone page will be mapped
 * @param result        Output: recompiled instructions + offset_map
 * @return 0 on success, -1 on error
 */
int dbi_recompile_page(const uint32_t *orig_insns, uint64_t orig_page_va,
                       uint64_t clone_page_va, dbi_result_t *result);

/**
 * Emit a far redirect (absolute branch to 64-bit address).
 * Used when relative branch range is exceeded.
 * @param out       Output buffer
 * @param target    Absolute target address
 * @return Number of instructions emitted
 */
uint32_t dbi_emit_far_redirect(uint32_t *out, uint64_t target);

/**
 * Emit a far call (absolute BL equivalent).
 * @param out       Output buffer
 * @param target    Absolute target address
 * @param ret_addr  Return address to store in LR
 * @return Number of instructions emitted
 */
uint32_t dbi_emit_far_call(uint32_t *out, uint64_t target, uint64_t ret_addr);

/**
 * Hook context passed to user callback.
 * Callback can read/modify args, skip original function, or replace return value.
 */
typedef struct {
    uint64_t args[8];       /* X0-X7: readable and writable by callback */
    uint64_t skip_origin;   /* non-zero: skip original function, use ret_value */
    uint64_t ret_value;     /* return value when skip_origin is set */
} xiaojianbang_hook_context_t;

/**
 * Inject a hook trampoline at a function entry in the clone page.
 * Appends trampoline code at the end of clone_insns and redirects
 * offset_map[target_insn_idx] to point to the trampoline.
 *
 * Callback signature: void callback(xiaojianbang_hook_context_t *ctx)
 *
 * Trampoline flow:
 *   1. Save X0-X7, X29, X30 to stack (forms hook_context.args[])
 *   2. Zero skip_origin and ret_value
 *   3. X0 = pointer to context, BLR callback
 *   4. If ctx->skip_origin != 0: return ctx->ret_value immediately
 *   5. Otherwise: restore args (callback may have modified them), B to original entry
 *
 * @param result          DBI result (modified in place)
 * @param target_insn_idx Index of target function's first instruction in original page
 * @param hook_callback   Absolute address of user hook function (takes xiaojianbang_hook_context_t*)
 * @param orig_page_addr  Original page address (unused in HWBP mode, kept for API compat)
 * @param pid             Target PID (unused in HWBP mode)
 * @param clone_page_va   Clone page base VA
 * @return 0 on success, -1 if clone page overflow
 */
int dbi_inject_entry_hook(dbi_result_t *result, uint32_t target_insn_idx,
                          uint64_t hook_callback, uint64_t orig_page_addr,
                          uint32_t pid, uint64_t clone_page_va);

#endif /* _SH_DBI_H_ */
