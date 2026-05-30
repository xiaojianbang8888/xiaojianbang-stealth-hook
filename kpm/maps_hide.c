/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook - Maps Hide (seq_file buffer truncation)
 *
 * Hooks the kernel's show_map_vma / show_smap functions to intercept
 * /proc/self/maps output. When a line matches our hidden entries,
 * we truncate the seq_file buffer to erase it.
 *
 * This hides both:
 * - Ghost memory (VMA-less, but some kernels may still show it)
 * - Regular mmap'd memory used by DBI engine (fallback mode)
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

/* Kernel function pointers */
extern void *(*kf_vmalloc)(unsigned long size);
extern void (*kf_vfree)(const void *addr);
extern unsigned long (*kf_copy_from_user)(void *to, const void __user *from, unsigned long n);

enum pid_type_maps {
    PIDTYPE_PID_MAPS,
    PIDTYPE_TGID_MAPS,
    PIDTYPE_PGID_MAPS,
    PIDTYPE_SID_MAPS,
    PIDTYPE_MAX_MAPS,
};

struct pid_namespace;
static pid_t (*kf_task_pid_nr_ns_maps)(struct task_struct *task, enum pid_type_maps type,
                                       struct pid_namespace *ns) = 0;

/* seq_file structure (minimal layout for buffer manipulation) */
struct sh_seq_file {
    char *buf;
    uint64_t size;
    uint64_t from;
    uint64_t count;     /* current write position in buffer */
    uint64_t pad_until;
    /* ... more fields we don't need */
};

#define SEQ_SKIP 1

/* Maps hide list */
static struct list_head maps_hide_list_head;
static int maps_hide_initialized = 0;

struct maps_hide_node {
    struct list_head list;
    uint64_t addr_start;
    uint64_t addr_end;
    uint32_t pid;
    char name[64];
};

static int show_map_hooked = 0;
static void *show_map_hook_fn = 0;

static void ensure_maps_hide_init(void)
{
    if (!maps_hide_initialized) {
        INIT_LIST_HEAD(&maps_hide_list_head);
        maps_hide_initialized = 1;
    }
    if (!kf_task_pid_nr_ns_maps)
        kf_task_pid_nr_ns_maps = (typeof(kf_task_pid_nr_ns_maps))kallsyms_lookup_name("__task_pid_nr_ns");
}

uint32_t sh_maps_current_tgid(void)
{
    ensure_maps_hide_init();
    if (!kf_task_pid_nr_ns_maps)
        return 0;
    return (uint32_t)kf_task_pid_nr_ns_maps(current, PIDTYPE_TGID_MAPS, 0);
}

static int bounded_contains(const char *line, uint64_t len, const char *needle)
{
    uint64_t i;
    uint64_t nlen = 0;

    while (needle[nlen]) nlen++;
    if (nlen == 0 || len < nlen)
        return 0;

    for (i = 0; i <= len - nlen; i++) {
        uint64_t j = 0;
        while (j < nlen && line[i + j] == needle[j]) j++;
        if (j == nlen)
            return 1;
    }
    return 0;
}

static uint64_t parse_line_start(const char *line, uint64_t len)
{
    uint64_t i;
    uint64_t value = 0;

    for (i = 0; i < len && line[i] != '-'; i++) {
        char c = line[i];
        if (c >= '0' && c <= '9') value = (value << 4) | (c - '0');
        else if (c >= 'a' && c <= 'f') value = (value << 4) | (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') value = (value << 4) | (c - 'A' + 10);
        else break;
    }
    return value;
}

static int should_hide_line(const char *line, uint64_t len, uint32_t pid)
{
    struct list_head *pos;
    struct maps_hide_node *node;

    for (pos = maps_hide_list_head.next; pos != &maps_hide_list_head; pos = pos->next) {
        node = (struct maps_hide_node *)((char *)pos -
               __builtin_offsetof(struct maps_hide_node, list));

        if (node->pid != 0 && node->pid != pid)
            continue;

        if (node->name[0] != '\0' && bounded_contains(line, len, node->name))
            return 1;

        if (node->addr_start != 0) {
            uint64_t line_start = parse_line_start(line, len);
            if (line_start >= node->addr_start && line_start < node->addr_end)
                return 1;
        }
    }
    return 0;
}

/*
 * Hook callback: called BEFORE show_map_vma writes to seq_file.
 * We save the current buffer position.
 */
static void maps_show_before(hook_fargs4_t *args, void *udata)
{
    struct sh_seq_file *m = (struct sh_seq_file *)args->arg0;
    /* Save current buffer write position */
    args->local.data0 = m->count;
}

/*
 * Hook callback: called AFTER show_map_vma writes to seq_file.
 * We check if the newly written line should be hidden.
 */
static void maps_show_after(hook_fargs4_t *args, void *udata)
{
    struct sh_seq_file *m = (struct sh_seq_file *)args->arg0;
    uint64_t prev_count = args->local.data0;
    uint64_t len_added;

    if (!m->buf || m->count <= prev_count || prev_count >= m->size)
        return;

    len_added = m->count - prev_count;
    if (len_added == 0 || prev_count + len_added > m->size)
        return;

    char *entry = m->buf + prev_count;
    uint32_t pid = sh_maps_current_tgid();

    if (should_hide_line(entry, len_added, pid)) {
        /* Truncate: rewind buffer position to before this entry */
        m->count = prev_count;
        m->pad_until = 0;
    }
}

static int install_maps_hook(void)
{
    void *show_map_fn;
    hook_err_t err;

    if (show_map_hooked)
        return 0;

    show_map_fn = (void *)kallsyms_lookup_name("show_map_vma");
    if (!show_map_fn)
        show_map_fn = (void *)kallsyms_lookup_name("show_vma");
    if (!show_map_fn)
        show_map_fn = (void *)kallsyms_lookup_name("show_map");
    if (!show_map_fn) {
        pr_err("[maps_hide] show_map symbol not found\n");
        return -1;
    }

    err = hook_wrap4(show_map_fn, maps_show_before, maps_show_after, 0);
    if (err != HOOK_NO_ERR) {
        pr_err("[maps_hide] failed to hook show_map: %d\n", err);
        return -1;
    }

    show_map_hooked = 1;
    show_map_hook_fn = show_map_fn;
    sh_dbg("[maps_hide] hooked show_map at %llx\n", (uint64_t)show_map_fn);
    return 0;
}

long sh_maps_hide_add_direct(uint64_t start, uint64_t end, uint32_t pid, const char *name)
{
    struct maps_hide_node *node;

    ensure_maps_hide_init();
    if (!kf_vmalloc)
        return -1;
    if (start && end <= start)
        return -1;

    if (install_maps_hook() < 0)
        return -1;

    node = (struct maps_hide_node *)kf_vmalloc(sizeof(struct maps_hide_node));
    if (!node)
        return -1;

    memset(node, 0, sizeof(*node));
    node->addr_start = start;
    node->addr_end = end;
    node->pid = pid;
    if (name) {
        int i;
        for (i = 0; i < (int)sizeof(node->name) - 1 && name[i]; i++)
            node->name[i] = name[i];
        node->name[i] = '\0';
    }

    node->list.next = maps_hide_list_head.next;
    node->list.prev = &maps_hide_list_head;
    maps_hide_list_head.next->prev = &node->list;
    maps_hide_list_head.next = &node->list;

    sh_dbg("[maps_hide] add: pid=%d, start=%llx, end=%llx, name=%s\n",
            pid, start, end, node->name);
    return 0;
}

long sh_maps_hide_add(struct sh_maps_hide_request __user *req)
{
    struct sh_maps_hide_request kreq;

    ensure_maps_hide_init();

    if (!kf_copy_from_user || kf_copy_from_user(&kreq, req, sizeof(kreq)))
        return -1;

    kreq.name[sizeof(kreq.name) - 1] = '\0';
    return sh_maps_hide_add_direct(kreq.addr_start, kreq.addr_end, kreq.target_pid, kreq.name);
}

long sh_maps_hide_remove(uint64_t addr, uint32_t pid)
{
    struct list_head *pos, *tmp;
    struct maps_hide_node *node;

    ensure_maps_hide_init();

    for (pos = maps_hide_list_head.next; pos != &maps_hide_list_head; pos = tmp) {
        tmp = pos->next;
        node = (struct maps_hide_node *)((char *)pos -
               __builtin_offsetof(struct maps_hide_node, list));

        if (node->addr_start == addr && node->pid == pid) {
            pos->prev->next = pos->next;
            pos->next->prev = pos->prev;
            kf_vfree(node);
            sh_dbg("[maps_hide] removed: addr=%llx, pid=%d\n", addr, pid);
            return 0;
        }
    }
    return -1;
}

void sh_maps_hide_cleanup(void)
{
    struct list_head *pos, *tmp;
    struct maps_hide_node *node;

    if (!maps_hide_initialized)
        return;

    for (pos = maps_hide_list_head.next; pos != &maps_hide_list_head; pos = tmp) {
        tmp = pos->next;
        node = (struct maps_hide_node *)((char *)pos -
               __builtin_offsetof(struct maps_hide_node, list));
        pos->prev->next = pos->next;
        pos->next->prev = pos->prev;
        kf_vfree(node);
    }

    if (show_map_hooked && show_map_hook_fn) {
        hook_unwrap(show_map_hook_fn, maps_show_before, maps_show_after);
        show_map_hooked = 0;
        show_map_hook_fn = 0;
    }
}
