/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook - Ghost Memory (Safe Implementation)
 *
 * Strategy: Use kernel's vm_mmap to allocate memory (creates proper VMA),
 * then hide it from /proc/self/maps via the Maps Hide module.
 *
 * This avoids raw PTE manipulation which caused kernel panics due to:
 * - Missing intermediate page table levels
 * - Incorrect linear mapping offset
 * - PAN violations
 *
 * End result is the same: memory is usable but invisible to maps scanning.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <kputils.h>
#include <asm/current.h>
#include <pgtable.h>
#include <ktypes.h>

#include "stealth_hook.h"

#ifndef INIT_LIST_HEAD
#define INIT_LIST_HEAD(ptr) do { (ptr)->next = (ptr); (ptr)->prev = (ptr); } while (0)
#endif

/* Kernel function pointers */
extern void *(*kf_vmalloc)(unsigned long size);
extern void (*kf_vfree)(const void *addr);
extern unsigned long (*kf_copy_from_user)(void *to, const void __user *from, unsigned long n);
extern struct task_struct *(*kf_find_task_by_vpid)(pid_t nr);
extern void *(*kf_get_task_mm)(struct task_struct *task);
extern void (*kf_mmput)(void *mm);

extern long sh_maps_hide_add_direct(uint64_t start, uint64_t end, uint32_t pid, const char *name);
extern long sh_maps_hide_remove(uint64_t addr, uint32_t pid);
extern uint32_t sh_maps_current_tgid(void);

/* Cross-process mm context switch via kthread_use_mm/kthread_unuse_mm */
static void (*kf_kthread_use_mm)(void *mm) = 0;
static void (*kf_kthread_unuse_mm)(void *mm) = 0;

static void resolve_mm_switch(void)
{
    if (!kf_kthread_use_mm) {
        kf_kthread_use_mm = (typeof(kf_kthread_use_mm))kallsyms_lookup_name("kthread_use_mm");
        kf_kthread_unuse_mm = (typeof(kf_kthread_unuse_mm))kallsyms_lookup_name("kthread_unuse_mm");
        if (!kf_kthread_use_mm) {
            /* Fallback for older kernels */
            kf_kthread_use_mm = (typeof(kf_kthread_use_mm))kallsyms_lookup_name("use_mm");
            kf_kthread_unuse_mm = (typeof(kf_kthread_unuse_mm))kallsyms_lookup_name("unuse_mm");
        }
    }
}

/* vm_mmap: allocate memory in current process with proper VMA */
static unsigned long (*kf_vm_mmap)(void *file, unsigned long addr, unsigned long len,
                                    unsigned long prot, unsigned long flags,
                                    unsigned long pgoff) = 0;
/* vm_munmap: free mmap'd memory */
static int (*kf_vm_munmap)(unsigned long start, unsigned long len) = 0;

/* Ghost memory list */
static struct list_head ghost_list_head;
static int ghost_list_initialized = 0;

struct ghost_node {
    struct list_head list;
    uint64_t user_va;
    uint64_t size;
    uint32_t pid;
    uint32_t prot;
};

static void ensure_ghost_list_init(void)
{
    if (!ghost_list_initialized) {
        INIT_LIST_HEAD(&ghost_list_head);
        ghost_list_initialized = 1;
    }
}

static void resolve_ghost_symbols(void)
{
    if (!kf_vm_mmap) {
        kf_vm_mmap = (typeof(kf_vm_mmap))kallsyms_lookup_name("vm_mmap");
        kf_vm_munmap = (typeof(kf_vm_munmap))kallsyms_lookup_name("vm_munmap");
        sh_dbg("[ghost] vm_mmap=%llx vm_munmap=%llx\n",
                (uint64_t)kf_vm_mmap, (uint64_t)kf_vm_munmap);
    }
}

/* Convert our prot flags to Linux mmap prot flags */
static unsigned long to_mmap_prot(uint32_t prot)
{
    unsigned long mp = 0;
    if (prot & SH_PROT_READ)  mp |= 0x1; /* PROT_READ */
    if (prot & SH_PROT_WRITE) mp |= 0x2; /* PROT_WRITE */
    if (prot & SH_PROT_EXEC)  mp |= 0x4; /* PROT_EXEC */
    return mp;
}

/*
 * Allocate ghost memory using vm_mmap (safe, creates proper VMA).
 * The Maps Hide module will hide it from /proc/self/maps.
 *
 * Cross-process support: when pid != 0 and pid != current TGID,
 * temporarily switch mm context to target process for vm_mmap.
 *
 * Direct args from syscall: arg1=va, arg2=size, arg3=pid, arg4=prot
 */
long sh_ghost_alloc_direct(uint64_t target_va, uint64_t size, uint32_t pid, uint32_t prot)
{
    struct ghost_node *node;
    unsigned long result;

    ensure_ghost_list_init();
    resolve_ghost_symbols();

    /* Align size to page boundary */
    size = (size + 4095) & ~4095ul;

    sh_dbg("[ghost] alloc: va=%llx, size=%llx, pid=%d, prot=%x\n",
            target_va, size, pid, prot);

    if (!kf_vm_mmap) {
        pr_err("[ghost] vm_mmap not resolved\n");
        return -1;
    }

    /* Cross-process: NOT supported in syscall context (kthread_use_mm panics).
     * Use /proc/pid/mem from userspace for cross-process writes instead. */
    uint32_t cur_tgid = sh_maps_current_tgid();
    if (pid != 0 && pid != cur_tgid) {
        pr_err("[ghost] cross-process alloc not supported via syscall, use /proc/pid/mem\n");
        return -95;
    }

    /* Allocate via vm_mmap (uses current->mm) */
    unsigned long flags = 0x22; /* MAP_PRIVATE | MAP_ANONYMOUS */
    if (target_va != 0)
        flags |= 0x10; /* MAP_FIXED */

    result = kf_vm_mmap(0, target_va, size, to_mmap_prot(prot), flags, 0);

    /* Restore mm if we swapped — no longer needed, cross-process disabled */

    if ((long)result < 0 || result >= 0xFFFFFFFF00000000ul) {
        pr_err("[ghost] vm_mmap failed: %lx\n", result);
        return -1;
    }

    sh_dbg("[ghost] vm_mmap success: va=%lx, size=%llx, pid=%d\n", result, size, pid);

    if (pid == 0)
        pid = cur_tgid;

    /* Record allocation */
    if (!kf_vmalloc) return (long)result;
    node = (struct ghost_node *)kf_vmalloc(sizeof(struct ghost_node));
    if (!node) return (long)result;

    node->user_va = result;
    node->size = size;
    node->pid = pid;
    node->prot = prot;

    node->list.next = ghost_list_head.next;
    node->list.prev = &ghost_list_head;
    ghost_list_head.next->prev = &node->list;
    ghost_list_head.next = &node->list;

    sh_maps_hide_add_direct(result, result + size, pid, 0);

    return (long)result;
}

/* Legacy pointer-based API */
long sh_ghost_alloc(struct sh_ghost_request __user *req)
{
    sh_dbg("[ghost] pointer-based alloc not supported (use direct args)\n");
    return -1;
}

long sh_ghost_free(uint64_t va, uint32_t pid)
{
    struct list_head *pos, *tmp;
    struct ghost_node *node;

    ensure_ghost_list_init();
    resolve_ghost_symbols();

    for (pos = ghost_list_head.next; pos != &ghost_list_head; pos = tmp) {
        tmp = pos->next;
        node = (struct ghost_node *)((char *)pos -
               __builtin_offsetof(struct ghost_node, list));

        if (node->user_va == va && (pid == 0 || node->pid == pid)) {
            /* Unmap memory */
            if (kf_vm_munmap) {
                kf_vm_munmap(node->user_va, node->size);
            }

            sh_maps_hide_remove(node->user_va, node->pid);

            /* Remove from list */
            pos->prev->next = pos->next;
            pos->next->prev = pos->prev;
            kf_vfree(node);

            sh_dbg("[ghost] free: va=%llx\n", va);
            return 0;
        }
    }
    return -1;
}

long sh_ghost_write(struct sh_ghost_write_request __user *req)
{
    struct sh_ghost_write_request kreq;
    struct list_head *pos;
    struct ghost_node *node;
    char buf[256];
    uint64_t copied_total;

    ensure_ghost_list_init();

    if (!kf_copy_from_user || kf_copy_from_user(&kreq, req, sizeof(kreq)))
        return -14;
    if (!kreq.target_va || !kreq.src_data || !kreq.size)
        return -22;

    for (pos = ghost_list_head.next; pos != &ghost_list_head; pos = pos->next) {
        node = (struct ghost_node *)((char *)pos -
               __builtin_offsetof(struct ghost_node, list));
        if (kreq.target_va >= node->user_va &&
            kreq.target_va + kreq.size <= node->user_va + node->size &&
            (kreq.target_pid == 0 || node->pid == kreq.target_pid)) {

            for (copied_total = 0; copied_total < kreq.size; ) {
                uint64_t remaining = kreq.size - copied_total;
                uint64_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
                int copied;

                if (kf_copy_from_user(buf, (void __user *)(kreq.src_data + copied_total), chunk))
                    return -14;

                copied = compat_copy_to_user((void __user *)(kreq.target_va + copied_total), buf, (int)chunk);
                if (copied != (int)chunk) {
                    pr_err("[ghost] write failed copied=%d expected=%d\n", copied, (int)chunk);
                    return -14;
                }
                copied_total += chunk;
            }

            sh_dbg("[ghost] write: va=%llx size=%llx pid=%d\n", kreq.target_va, kreq.size, node->pid);
            return 0;
        }
    }

    return -2;
}

void sh_ghost_cleanup(void)
{
    struct list_head *pos, *tmp;
    struct ghost_node *node;

    ensure_ghost_list_init();
    resolve_ghost_symbols();

    for (pos = ghost_list_head.next; pos != &ghost_list_head; pos = tmp) {
        tmp = pos->next;
        node = (struct ghost_node *)((char *)pos -
               __builtin_offsetof(struct ghost_node, list));
        if (kf_vm_munmap)
            kf_vm_munmap(node->user_va, node->size);
        sh_maps_hide_remove(node->user_va, node->pid);
        pos->prev->next = pos->next;
        pos->next->prev = pos->prev;
        kf_vfree(node);
    }
}
