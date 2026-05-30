/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook - DBI ARM64 Instruction Decoder
 * Classifies instructions by their PC-relative behavior
 */

#include "dbi.h"
#include <string.h>

/* ARM64 instruction field extraction helpers */
#define BITS(insn, hi, lo)  (((insn) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1))
#define SIGN_EXTEND(val, bits) \
    ((int64_t)((uint64_t)(val) << (64 - (bits))) >> (64 - (bits)))

void dbi_decode(uint32_t insn, uint64_t pc, dbi_decoded_t *out)
{
    memset(out, 0, sizeof(*out));
    out->raw = insn;
    out->type = INSN_NORMAL;

    /* B / BL: unconditional branch immediate */
    if ((insn & 0x7C000000) == 0x14000000) {
        int64_t imm26 = SIGN_EXTEND(insn & 0x03FFFFFF, 26);
        out->imm = imm26 * 4;
        out->is_link = (insn >> 31) & 1;  /* bit 31: 1=BL, 0=B */
        out->type = out->is_link ? INSN_BL : INSN_B;
        return;
    }

    /* B.cond: conditional branch */
    if ((insn & 0xFF000010) == 0x54000000) {
        int64_t imm19 = SIGN_EXTEND(BITS(insn, 23, 5), 19);
        out->imm = imm19 * 4;
        out->cond = insn & 0xF;
        out->type = INSN_BCOND;
        return;
    }

    /* CBZ / CBNZ */
    if ((insn & 0x7E000000) == 0x34000000) {
        int64_t imm19 = SIGN_EXTEND(BITS(insn, 23, 5), 19);
        out->imm = imm19 * 4;
        out->rn = insn & 0x1F;
        out->is_link = (insn >> 24) & 1;  /* bit 24: 1=CBNZ, 0=CBZ */
        out->type = INSN_CBZ;
        return;
    }

    /* TBZ / TBNZ */
    if ((insn & 0x7E000000) == 0x36000000) {
        int64_t imm14 = SIGN_EXTEND(BITS(insn, 18, 5), 14);
        out->imm = imm14 * 4;
        out->rn = insn & 0x1F;
        out->is_link = (insn >> 24) & 1;  /* bit 24: 1=TBNZ, 0=TBZ */
        out->bit_pos = (BITS(insn, 23, 19)) | ((insn >> 31) << 5);
        out->type = INSN_TBZ;
        return;
    }

    /* ADRP */
    if ((insn & 0x9F000000) == 0x90000000) {
        int64_t immhi = SIGN_EXTEND(BITS(insn, 23, 5), 19);
        int64_t immlo = BITS(insn, 30, 29);
        out->imm = ((immhi << 2) | immlo) << 12;
        out->rd = insn & 0x1F;
        out->type = INSN_ADRP;
        return;
    }

    /* ADR */
    if ((insn & 0x9F000000) == 0x10000000) {
        int64_t immhi = SIGN_EXTEND(BITS(insn, 23, 5), 19);
        int64_t immlo = BITS(insn, 30, 29);
        out->imm = (immhi << 2) | immlo;
        out->rd = insn & 0x1F;
        out->type = INSN_ADR;
        return;
    }

    /* LDR (literal) - 32/64-bit and SIMD variants */
    if ((insn & 0x3B000000) == 0x18000000) {
        int64_t imm19 = SIGN_EXTEND(BITS(insn, 23, 5), 19);
        out->imm = imm19 * 4;
        out->rd = insn & 0x1F;
        out->type = INSN_LDR_LIT;
        return;
    }

    /* BLR / BLRAA / BLRAB / BLRAAZ / BLRABZ */
    if ((insn & 0xFFFFFC1F) == 0xD63F0000 ||  /* BLR Xn */
        (insn & 0xFEFFF800) == 0xD63F0800) {  /* BLRA* variants */
        out->rn = BITS(insn, 9, 5);
        out->is_link = 1;
        out->type = INSN_BLR;
        return;
    }

    /* BR / BRAA / BRAB (without link) */
    if ((insn & 0xFFFFFC1F) == 0xD61F0000 ||
        (insn & 0xFEFFF800) == 0xD61F0800) {
        out->rn = BITS(insn, 9, 5);
        out->is_link = 0;
        out->type = INSN_NORMAL; /* BR doesn't need rewrite, it's register-based */
        return;
    }

    /* RET */
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) {
        out->rn = BITS(insn, 9, 5);
        out->type = INSN_RET;
        return;
    }

    /* Everything else: normal instruction, copy as-is */
    out->type = INSN_NORMAL;
}
