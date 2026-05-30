/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook - DBI ARM64 Instruction Recompiler
 *
 * Rewrites PC-relative instructions to work at a different address.
 * Handles: B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, ADRP, ADR, LDR literal, BLR
 */

#include "dbi.h"
#include <string.h>

/* Encode helpers */
static inline void emit_u64(uint32_t *out, uint64_t val)
{
    out[0] = (uint32_t)(val & 0xFFFFFFFF);
    out[1] = (uint32_t)(val >> 32);
}

static inline uint32_t encode_ldr_lit64(uint32_t rt, int32_t offset_bytes)
{
    /* LDR Xt, [PC, #offset] — literal load, 64-bit */
    int32_t imm19 = offset_bytes / 4;
    return 0x58000000 | ((imm19 & 0x7FFFF) << 5) | rt;
}

static inline uint32_t encode_b(int32_t offset_bytes)
{
    /* B #offset */
    int32_t imm26 = offset_bytes / 4;
    return 0x14000000 | (imm26 & 0x03FFFFFF);
}

/*
 * Emit far redirect: absolute branch to 64-bit address.
 * Uses X17 as scratch (caller-saved, safe to clobber).
 *
 * Generated code (11 instructions):
 *   STR X17, [SP, #-16]!     ; save X17
 *   LDR X17, [PC, #16]       ; load target address
 *   ADD SP, SP, #16          ; restore SP
 *   BR X17                   ; jump
 *   <8 bytes: target address literal>
 *   LDR X17, [SP, #-16]      ; (never reached, but keeps stack balanced for analysis)
 *
 * Simplified version (7 instructions):
 *   LDR X17, [PC, #8]        ; load 64-bit target from literal pool
 *   BR X17                   ; unconditional jump
 *   <target_addr: 8 bytes>   ; literal data
 */
uint32_t dbi_emit_far_redirect(uint32_t *out, uint64_t target)
{
    out[0] = encode_ldr_lit64(17, 8);   /* LDR X17, [PC, #8] */
    out[1] = 0xD61F0220;                /* BR X17 */
    emit_u64(&out[2], target);          /* 64-bit target address */
    return 4; /* 4 instruction slots (2 insns + 2 data words) */
}

/*
 * Emit far call: absolute BL equivalent.
 * Stores return address in LR (X30), then jumps to target.
 *
 * Generated code:
 *   LDR X30, [PC, #12]       ; load return address into LR
 *   LDR X17, [PC, #12]       ; load target address
 *   BR X17                   ; jump (LR already set)
 *   <ret_addr: 8 bytes>
 *   <target: 8 bytes>
 */
uint32_t dbi_emit_far_call(uint32_t *out, uint64_t target, uint64_t ret_addr)
{
    out[0] = encode_ldr_lit64(30, 12);  /* LDR X30, [PC, #12] */
    out[1] = encode_ldr_lit64(17, 12);  /* LDR X17, [PC, #12] */
    out[2] = 0xD61F0220;                /* BR X17 */
    emit_u64(&out[3], ret_addr);        /* return address literal */
    emit_u64(&out[5], target);          /* target address literal */
    return 7; /* 7 slots */
}

/*
 * Emit recompiled B.cond / CBZ / TBZ with out-of-range target.
 * Strategy: invert condition, skip over far redirect.
 *
 * For B.cond:
 *   B.!cond skip            ; inverted condition, skip far jump
 *   <far_redirect to target>
 *   skip:                   ; fall-through continues here
 */
static uint32_t emit_cond_far(uint32_t *out, dbi_decoded_t *dec,
                              uint64_t target, uint64_t fallthrough)
{
    uint32_t count = 0;

    switch (dec->type) {
    case INSN_BCOND: {
        /* Invert condition: flip bit 0 */
        uint32_t inv_cond = dec->cond ^ 1;
        /* B.inv_cond +8 (skip 4 slots of far redirect) */
        uint32_t skip_offset = (4 + 1) * 4; /* far_redirect is 4 slots */
        out[count++] = 0x54000000 | (((skip_offset / 4) & 0x7FFFF) << 5) | inv_cond;
        break;
    }
    case INSN_CBZ: {
        /* Invert: CBZ -> CBNZ or CBNZ -> CBZ */
        uint32_t base = dec->is_link ? 0x34000000 : 0x35000000; /* swap */
        uint32_t sf = (dec->raw >> 31) & 1;
        uint32_t skip_offset = (4 + 1) * 4;
        out[count++] = (sf << 31) | base | (((skip_offset / 4) & 0x7FFFF) << 5) | dec->rn;
        break;
    }
    case INSN_TBZ: {
        /* Invert: TBZ -> TBNZ or TBNZ -> TBZ */
        uint32_t base_insn = dec->raw ^ (1 << 24); /* flip bit 24 */
        uint32_t skip_offset = (4 + 1) * 4;
        int32_t imm14 = skip_offset / 4;
        base_insn = (base_insn & ~(0x3FFF << 5)) | ((imm14 & 0x3FFF) << 5);
        out[count++] = base_insn;
        break;
    }
    default:
        return 0;
    }

    /* Emit far redirect to original target */
    count += dbi_emit_far_redirect(&out[count], target);

    return count;
}

/*
 * Recompile a full page of ARM64 instructions.
 * Two-pass algorithm:
 *   Pass 1: Decode all instructions, compute layout (offset_map)
 *   Pass 2: Emit recompiled instructions with correct offsets
 */
int dbi_recompile_page(const uint32_t *orig_insns, uint64_t orig_page_va,
                       uint64_t clone_page_va, dbi_result_t *result)
{
    memset(result, 0, sizeof(*result));

    /* Pass 1: Compute layout - determine how many slots each instruction needs */
    uint32_t total_slots = 0;

    for (int i = 0; i < DBI_INSN_PER_PAGE; i++) {
        dbi_decoded_t dec;
        uint64_t insn_pc = orig_page_va + (uint64_t)i * 4;
        dbi_decode(orig_insns[i], insn_pc, &dec);

        uint32_t slots = 1; /* default: 1 slot (copy as-is) */

        switch (dec.type) {
        case INSN_B:
            slots = 4; /* far redirect: LDR X17 + BR X17 + 8-byte addr */
            break;
        case INSN_BL:
            slots = 7; /* far call: LDR X30 + LDR X17 + BR X17 + 2x 8-byte */
            break;
        case INSN_BCOND:
        case INSN_CBZ:
        case INSN_TBZ:
            slots = 5; /* inverted cond (1) + far redirect (4) */
            break;
        case INSN_ADRP:
        case INSN_ADR:
            slots = 4; /* LDR literal + B skip + 8-byte data */
            break;
        case INSN_LDR_LIT:
            slots = 5; /* LDR scratch + B skip + 8-byte addr + LDR Rd,[scratch] */
            break;
        case INSN_BLR:
            slots = 4; /* LDR X30 + modified BR + 8-byte literal */
            break;
        default:
            slots = 1;
            break;
        }

        result->offset_map[i] = total_slots;
        total_slots += slots;
    }

    if (total_slots > DBI_CLONE_MAX_INSNS) {
        return -1; /* clone page too large */
    }

    /* Pass 2: Emit recompiled instructions */
    uint32_t out_idx = 0;

    for (int i = 0; i < DBI_INSN_PER_PAGE; i++) {
        dbi_decoded_t dec;
        uint64_t insn_pc = orig_page_va + (uint64_t)i * 4;
        dbi_decode(orig_insns[i], insn_pc, &dec);

        uint64_t target_abs; /* absolute target address for branches */

        switch (dec.type) {
        case INSN_NORMAL:
        case INSN_RET:
            /* Copy as-is */
            result->clone_insns[out_idx++] = dec.raw;
            break;

        case INSN_B:
            /* Unconditional branch → far redirect */
            target_abs = insn_pc + dec.imm;
            out_idx += dbi_emit_far_redirect(&result->clone_insns[out_idx], target_abs);
            break;

        case INSN_BL:
            /* Branch with link → far call */
            target_abs = insn_pc + dec.imm;
            {
                /* Return address = next original instruction's clone position */
                uint64_t ret_addr;
                if (i + 1 < DBI_INSN_PER_PAGE)
                    ret_addr = clone_page_va + (uint64_t)result->offset_map[i + 1] * 4;
                else
                    ret_addr = orig_page_va + DBI_PAGE_SIZE; /* past end of page */
                out_idx += dbi_emit_far_call(&result->clone_insns[out_idx], target_abs, ret_addr);
            }
            break;

        case INSN_BCOND:
        case INSN_CBZ:
        case INSN_TBZ:
            /* Conditional branch → invert + far redirect */
            target_abs = insn_pc + dec.imm;
            out_idx += emit_cond_far(&result->clone_insns[out_idx], &dec,
                                     target_abs, 0);
            break;

        case INSN_ADRP:
            /* ADRP Rd, #imm → compute absolute, load via LDR literal */
            {
                uint64_t page_base = insn_pc & ~0xFFFul;
                uint64_t abs_val = page_base + dec.imm;
                result->clone_insns[out_idx] = encode_ldr_lit64(dec.rd, 8);
                result->clone_insns[out_idx + 1] = encode_b(12); /* skip data */
                emit_u64(&result->clone_insns[out_idx + 2], abs_val);
                out_idx += 4;
            }
            break;

        case INSN_ADR:
            /* ADR Rd, #imm → same treatment as ADRP */
            {
                uint64_t abs_val = insn_pc + dec.imm;
                result->clone_insns[out_idx] = encode_ldr_lit64(dec.rd, 8);
                result->clone_insns[out_idx + 1] = encode_b(12);
                emit_u64(&result->clone_insns[out_idx + 2], abs_val);
                out_idx += 4;
            }
            break;

        case INSN_LDR_LIT:
            /* LDR Rt, [PC, #imm] → load value at PC-relative address.
             * Strategy: load absolute data address into scratch reg, then LDR Rd from it.
             * Uses X17 as scratch (or X16 if Rd==X17). */
            {
                uint64_t data_addr = insn_pc + dec.imm;
                uint32_t opc = (dec.raw >> 30) & 0x3;
                uint32_t scratch = 17;
                if (dec.rd == 17) scratch = 16;

                /* LDR scratch, [PC, #8] — load absolute address of data */
                result->clone_insns[out_idx] = encode_ldr_lit64(scratch, 8);
                /* B +12 — skip over the 8-byte literal */
                result->clone_insns[out_idx + 1] = encode_b(12);
                /* 8-byte literal: the absolute address where data lives */
                emit_u64(&result->clone_insns[out_idx + 2], data_addr);
                /* LDR Rd, [scratch] — dereference to get actual value */
                if (opc == 0x01) /* 64-bit LDR */
                    result->clone_insns[out_idx + 4] = 0xF9400000 | (scratch << 5) | dec.rd;
                else /* 32-bit LDR (opc==0x00) or LDRSW (opc==0x10) */
                    result->clone_insns[out_idx + 4] = 0xB9400000 | (scratch << 5) | dec.rd;
                out_idx += 5;
            }
            break;

        case INSN_BLR:
            /* BLR Xn → set LR to correct return address, then BR Xn
             * Also handles PAC variants (BLRAAZ etc.) by clearing bit 21 */
            {
                uint64_t lr_val;
                if (i + 1 < DBI_INSN_PER_PAGE)
                    lr_val = clone_page_va + (uint64_t)result->offset_map[i + 1] * 4;
                else
                    lr_val = orig_page_va + DBI_PAGE_SIZE;

                /* LDR X30, [PC, #8] — load correct LR */
                result->clone_insns[out_idx] = encode_ldr_lit64(30, 8);
                /* Convert BLR to BR: clear bit 21 */
                uint32_t br_insn = dec.raw & ~(1u << 21);
                result->clone_insns[out_idx + 1] = br_insn;
                emit_u64(&result->clone_insns[out_idx + 2], lr_val);
                out_idx += 4;
            }
            break;

        default:
            result->clone_insns[out_idx++] = dec.raw;
            break;
        }
    }

    result->clone_count = out_idx;
    return 0;
}

/*
 * Inject a hook trampoline using xiaojianbang_hook_context_t.
 * Callback receives pointer to context on stack.
 *
 * Stack layout (160 bytes, 16-byte aligned):
 *   [SP+0]   X29, X30
 *   [SP+16]  args[0], args[1]   (= context base)
 *   [SP+32]  args[2], args[3]
 *   [SP+48]  args[4], args[5]
 *   [SP+64]  args[6], args[7]
 *   [SP+80]  skip_origin
 *   [SP+88]  ret_value
 *   [SP+96..159] padding
 */
int dbi_inject_entry_hook(dbi_result_t *result, uint32_t target_insn_idx,
                          uint64_t hook_callback, uint64_t orig_page_addr,
                          uint32_t pid, uint64_t clone_page_va)
{
    (void)orig_page_addr; (void)pid;

    uint32_t tramp_start = result->clone_count;
    uint32_t *out = &result->clone_insns[tramp_start];
    uint32_t n = 0;

    if (tramp_start + 30 > DBI_CLONE_MAX_INSNS)
        return -1;

    uint32_t orig_entry_clone_offset = result->offset_map[target_insn_idx];

    /* Prologue */
    out[n++] = 0xD10283FF; /* SUB SP, SP, #160 */
    out[n++] = 0xA9007BFD; /* STP X29, X30, [SP, #0] */
    out[n++] = 0x910003FD; /* MOV X29, SP */

    /* Store args[0..7] at [SP+16..SP+80] */
    out[n++] = 0xA90107E0; /* STP X0, X1, [SP, #16] */
    out[n++] = 0xA9020FE2; /* STP X2, X3, [SP, #32] */
    out[n++] = 0xA90317E4; /* STP X4, X5, [SP, #48] */
    out[n++] = 0xA9041FE6; /* STP X6, X7, [SP, #64] */

    /* Zero skip_origin and ret_value: STR XZR, [SP, #80]; STR XZR, [SP, #88] */
    out[n++] = 0xF9002BFF; /* STR XZR, [SP, #80] */
    out[n++] = 0xF9002FFF; /* STR XZR, [SP, #88] */

    /* X0 = &context (SP + 16) */
    out[n++] = 0x910043E0; /* ADD X0, SP, #16 */

    /* BLR callback */
    out[n++] = encode_ldr_lit64(17, 12); /* LDR X17, [PC, #12] */
    out[n++] = 0xD63F0220;              /* BLR X17 */
    out[n++] = encode_b(12);            /* B +12 (skip literal) */
    emit_u64(&out[n], hook_callback);
    n += 2;

    /* Check skip_origin: LDR X9, [SP, #80]; CBNZ X9, +skip */
    out[n++] = 0xF9402BE9; /* LDR X9, [SP, #80] */
    /* CBNZ X9, skip_path (7 insns ahead: restore + B = 7 insns, skip is at +8) */
    out[n++] = 0xB5000109; /* CBNZ X9, +8 insns (offset=8*4=32 → imm19=8) */

    /* Normal path: reload args (callback may have modified them), branch to orig */
    out[n++] = 0xA94107E0; /* LDP X0, X1, [SP, #16] */
    out[n++] = 0xA9420FE2; /* LDP X2, X3, [SP, #32] */
    out[n++] = 0xA94317E4; /* LDP X4, X5, [SP, #48] */
    out[n++] = 0xA9441FE6; /* LDP X6, X7, [SP, #64] */
    out[n++] = 0xA9407BFD; /* LDP X29, X30, [SP, #0] */
    out[n++] = 0x910283FF; /* ADD SP, SP, #160 */
    /* B to original recompiled entry */
    {
        uint32_t b_pos = tramp_start + n;
        int32_t b_off = (int32_t)(orig_entry_clone_offset - b_pos);
        out[n++] = 0x14000000 | (b_off & 0x03FFFFFF);
    }

    /* Skip path: load ret_value into X0, restore frame, RET */
    out[n++] = 0xF9402FE0; /* LDR X0, [SP, #88] (ret_value) */
    out[n++] = 0xA9407BFD; /* LDP X29, X30, [SP, #0] */
    out[n++] = 0x910283FF; /* ADD SP, SP, #160 */
    out[n++] = 0xD65F03C0; /* RET */

    result->clone_count = tramp_start + n;
    result->offset_map[target_insn_idx] = tramp_start;

    return 0;
}
