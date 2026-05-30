/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook - PTE/UXN Control + RVH Tracepoint Interception
 *
 * Hook strategy: Use Android GKI's android_rvh_do_mem_abort RVH tracepoint.
 * This is the ONLY safe approach on CFI-enabled GKI kernels because:
 * - hook_wrap: trampoline triggers recursive page faults (stack overflow)
 * - fp_hook_wrap: same trampoline recursion issue
 * - direct pointer replacement: CFI validates all indirect calls (panic)
 * - RVH tracepoint: designed for vendor modules, CFI-safe, no recursion
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

#define PAGE_MASK_4K (~0xFFFul)
#define PTE_UXN_BIT (1ul << 54)
#define PTE_VALID   (1ul << 0)
#define PTE_ADDR_MASK_ 0x0000FFFFFFFFF000ul

struct pte_pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

extern void *(*kf_vmalloc)(unsigned long size);
extern void (*kf_vfree)(const void *addr);
extern unsigned long (*kf_copy_from_user)(void *to, const void __user *from, unsigned long n);
extern uint64_t *kf_swapper_pg_dir;
extern void *(*kf_get_task_mm)(struct task_struct *task);
extern void (*kf_mmput)(void *mm);
extern int (*kf_apply_to_page_range)(void *mm, unsigned long addr, unsigned long size,
                                     int (*fn)(void *, unsigned long, void *), void *data);

/* PID resolution */
static pid_t (*kf_task_pid_nr_ns_pte)(void *task, int type, void *ns) = 0;

static uint32_t pte_current_tgid(void)
{
    if (!kf_task_pid_nr_ns_pte)
        kf_task_pid_nr_ns_pte = (typeof(kf_task_pid_nr_ns_pte))
            kallsyms_lookup_name("__task_pid_nr_ns");
    if (!kf_task_pid_nr_ns_pte)
        return 0;
    return (uint32_t)kf_task_pid_nr_ns_pte(current, 1, 0);
}

/* TLB flush for user-space page */
static inline void flush_tlb_user_page(uint64_t va)
{
    uint64_t page = va >> 12;
    asm volatile(
        "dsb ishst\n"
        "tlbi vale1is, %0\n"
        "dsb ish\n"
        "isb\n"
        :: "r"(page) : "memory"
    );
}

/* Page table access via apply_to_page_range() callback.
 * This correctly handles KASLR and all page table levels.
 * The callback receives the PTE virtual address directly from the kernel. */
struct pte_extract_data {
    uint64_t *ptep;  /* output: pointer to PTE entry */
};

static int extract_pte_cb(void *ptep_void, unsigned long addr, void *data)
{
    struct pte_extract_data *d = (struct pte_extract_data *)data;
    d->ptep = (uint64_t *)ptep_void;
    return 0;
}

/* Get PTE for a user-space VA in current process using apply_to_page_range.
 * Must be called from the target process context (e.g., during syscall). */
static uint64_t *get_user_pte(uint64_t va)
{
    struct pte_extract_data data = { .ptep = 0 };

    if (!kf_apply_to_page_range || !kf_get_task_mm)
        return 0;

    void *mm = kf_get_task_mm(current);
    if (!mm)
        return 0;

    kf_apply_to_page_range(mm, (unsigned long)va, 4096, extract_pte_cb, &data);
    kf_mmput(mm);

    return data.ptep;
}

/* PTE hook node list */
static struct list_head pte_hook_list;
static int pte_list_initialized = 0;

struct pte_hook_node {
    struct list_head list;
    uint64_t orig_page_addr;
    uint64_t recomp_page_addr;
    uint32_t pid;
    uint32_t offset_map[SH_INSN_PER_PAGE];
    uint64_t orig_pte_val;
    uint64_t *ptep;
};

static void ensure_pte_list_init(void)
{
    if (!pte_list_initialized) {
        INIT_LIST_HEAD(&pte_hook_list);
        pte_list_initialized = 1;
    }
}

static struct pte_hook_node *find_pte_node(uint64_t fault_page, uint32_t pid)
{
    struct list_head *pos;
    struct pte_hook_node *node;
    for (pos = pte_hook_list.next; pos != &pte_hook_list; pos = pos->next) {
        node = (struct pte_hook_node *)((char *)pos -
               __builtin_offsetof(struct pte_hook_node, list));
        if (node->orig_page_addr == fault_page && node->pid == pid)
            return node;
    }
    return 0;
}

/* RVH tracepoint registration */
static int (*kf_tracepoint_probe_register)(void *tp, void *probe, void *data) = 0;
static int (*kf_tracepoint_probe_unregister)(void *tp, void *probe, void *data) = 0;
static void *rvh_tracepoint = 0;
static int pte_fault_hooked = 0;

/* Find PTE hook node by fault page only (no PID filter in hot path).
 * CFI kernels cannot safely call kallsyms-resolved functions from fault context. */
static struct pte_hook_node *find_pte_node_by_page(uint64_t fault_page)
{
    struct list_head *pos;
    struct pte_hook_node *node;
    for (pos = pte_hook_list.next; pos != &pte_hook_list; pos = pos->next) {
        node = (struct pte_hook_node *)((char *)pos -
               __builtin_offsetof(struct pte_hook_node, list));
        if (node->orig_page_addr == fault_page)
            return node;
    }
    return 0;
}

/* RVH callback for android_rvh_do_mem_abort
 * Signature: void(void *data, unsigned long addr, unsigned long esr, struct pt_regs *regs)
 *
 * CRITICAL: After modifying regs->pc, we must also temporarily restore the PTE
 * (remove UXN) so the kernel's fault handler sees a valid page and doesn't send
 * SIGSEGV. The fault handler calls handle_mm_fault which re-walks the page table.
 * We then immediately re-arm UXN for next fault interception.
 *
 * Do NOT call any function resolved via kallsyms in this path (CFI issue). */
static void pte_rvh_callback(void *data, unsigned long addr,
                              unsigned long esr, struct pte_pt_regs *regs)
{
    uint32_t ec = (esr >> 26) & 0x3F;
    if (ec != 0x20)
        return;
    if (!pte_list_initialized)
        return;

    uint64_t fault_page = addr & PAGE_MASK_4K;
    uint32_t insn_idx = (uint32_t)((addr & ~PAGE_MASK_4K) / 4);

    struct pte_hook_node *node = find_pte_node_by_page(fault_page);
    if (!node || insn_idx >= SH_INSN_PER_PAGE)
        return;

    /* Redirect PC to clone page */
    uint32_t target_offset = node->offset_map[insn_idx];
    regs->pc = node->recomp_page_addr + ((uint64_t)target_offset * 4);

    /* Temporarily restore PTE (remove UXN) so fault handler sees valid page.
     * Without this, the kernel sends SIGSEGV after our callback returns.
     * handle_mm_fault() re-walks the page table and must see valid permissions.
     *
     * We do NOT re-arm UXN here — the fault handler runs AFTER this callback
     * returns and would see UXN again, causing an infinite loop.
     * UXN is re-armed on the next syscall bridge call (SH_CMD_PTE_REARM). */
    if (node->ptep) {
        *(volatile uint64_t *)node->ptep = node->orig_pte_val;
        flush_tlb_user_page(node->orig_page_addr);
    }
}

static int ensure_fault_hook(void)
{
    if (pte_fault_hooked)
        return 0;

    if (!kf_tracepoint_probe_register) {
        kf_tracepoint_probe_register = (typeof(kf_tracepoint_probe_register))
            kallsyms_lookup_name("tracepoint_probe_register");
        kf_tracepoint_probe_unregister = (typeof(kf_tracepoint_probe_unregister))
            kallsyms_lookup_name("tracepoint_probe_unregister");
    }
    if (!kf_tracepoint_probe_register || !kf_tracepoint_probe_unregister)
        return -1;

    rvh_tracepoint = (void *)kallsyms_lookup_name("__tracepoint_android_rvh_do_mem_abort");
    if (!rvh_tracepoint)
        return -1;

    int ret = kf_tracepoint_probe_register(rvh_tracepoint, pte_rvh_callback, 0);
    if (ret)
        return -1;

    pte_fault_hooked = 1;
    sh_dbg("[pte_hook] android_rvh_do_mem_abort registered\n");
    return 0;
}

void sh_pte_unhook_fault(void)
{
    if (pte_fault_hooked && rvh_tracepoint && kf_tracepoint_probe_unregister) {
        kf_tracepoint_probe_unregister(rvh_tracepoint, pte_rvh_callback, 0);
        pte_fault_hooked = 0;
    }
}

/* Public API */
long sh_pte_hook(struct sh_pte_request __user *req)
{
    struct sh_pte_request kreq;
    struct pte_hook_node *node;

    ensure_pte_list_init();

    if (ensure_fault_hook() < 0)
        return -95;

    if (!kf_copy_from_user || kf_copy_from_user(&kreq, req, sizeof(kreq)))
        return -14;

    if (kreq.orig_page_addr & 0xFFF)
        return -22;

    if (!kf_vmalloc) return -12;
    node = (struct pte_hook_node *)kf_vmalloc(sizeof(struct pte_hook_node));
    if (!node) return -12;

    memset(node, 0, sizeof(*node));
    node->orig_page_addr = kreq.orig_page_addr;
    node->recomp_page_addr = kreq.recomp_page_addr;
    node->pid = kreq.target_pid;
    memcpy(node->offset_map, kreq.offset_map, sizeof(kreq.offset_map));

    /* Set UXN on target page using apply_to_page_range */
    if (!kf_apply_to_page_range || !kf_get_task_mm) {
        kf_vfree(node);
        return -1;
    }
    uint64_t *ptep = get_user_pte(kreq.orig_page_addr);
    if (!ptep || !(*(volatile uint64_t *)ptep & PTE_VALID)) {
        kf_vfree(node);
        return -1;
    }
    node->orig_pte_val = *(volatile uint64_t *)ptep;
    node->ptep = ptep;
    *(volatile uint64_t *)ptep = node->orig_pte_val | PTE_UXN_BIT;
    flush_tlb_user_page(kreq.orig_page_addr);

    node->list.next = pte_hook_list.next;
    node->list.prev = &pte_hook_list;
    pte_hook_list.next->prev = &node->list;
    pte_hook_list.next = &node->list;

    sh_dbg("[pte_hook] UXN set page=%llx pid=%d\n",
            (unsigned long long)kreq.orig_page_addr, kreq.target_pid);
    return 0;
}

long sh_pte_unhook(uint64_t page_addr, uint32_t pid)
{
    struct list_head *pos, *tmp;
    struct pte_hook_node *node;
    ensure_pte_list_init();

    for (pos = pte_hook_list.next; pos != &pte_hook_list; pos = tmp) {
        tmp = pos->next;
        node = (struct pte_hook_node *)((char *)pos -
               __builtin_offsetof(struct pte_hook_node, list));
        if (node->orig_page_addr == page_addr && node->pid == pid) {
            if (node->ptep) {
                *(volatile uint64_t *)node->ptep = node->orig_pte_val;
                flush_tlb_user_page(node->orig_page_addr);
            }
            pos->prev->next = pos->next;
            pos->next->prev = pos->prev;
            kf_vfree(node);
            return 0;
        }
    }
    return -2;
}

/* Re-arm UXN on a previously hooked page (restore interception after fault) */
long sh_pte_rearm(uint64_t page_addr, uint32_t pid)
{
    struct list_head *pos;
    struct pte_hook_node *node;
    ensure_pte_list_init();

    for (pos = pte_hook_list.next; pos != &pte_hook_list; pos = pos->next) {
        node = (struct pte_hook_node *)((char *)pos -
               __builtin_offsetof(struct pte_hook_node, list));
        if (node->orig_page_addr == page_addr && (pid == 0 || node->pid == pid)) {
            if (node->ptep) {
                *(volatile uint64_t *)node->ptep = node->orig_pte_val | PTE_UXN_BIT;
                flush_tlb_user_page(node->orig_page_addr);
                return 0;
            }
            return -1;
        }
    }
    return -2;
}

long sh_pte_commit_dbi(struct sh_pte_request __user *req)
{
    struct sh_pte_request kreq;
    struct pte_hook_node *node;
    ensure_pte_list_init();

    if (!kf_copy_from_user || kf_copy_from_user(&kreq, req, sizeof(kreq)))
        return -14;

    node = find_pte_node(kreq.orig_page_addr, kreq.target_pid);
    if (!node)
        return sh_pte_hook(req);

    node->recomp_page_addr = kreq.recomp_page_addr;
    memcpy(node->offset_map, kreq.offset_map, sizeof(kreq.offset_map));
    return 0;
}

void sh_pte_cleanup(void)
{
    struct list_head *pos, *tmp;
    struct pte_hook_node *node;
    if (!pte_list_initialized)
        return;

    for (pos = pte_hook_list.next; pos != &pte_hook_list; pos = tmp) {
        tmp = pos->next;
        node = (struct pte_hook_node *)((char *)pos -
               __builtin_offsetof(struct pte_hook_node, list));
        if (node->ptep) {
            *(volatile uint64_t *)node->ptep = node->orig_pte_val;
            flush_tlb_user_page(node->orig_page_addr);
        }
        pos->prev->next = pos->next;
        pos->next->prev = pos->prev;
        kf_vfree(node);
    }
}
