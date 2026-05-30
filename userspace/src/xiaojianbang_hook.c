/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xiaojianbang_hook — Zero-trace stealth hook tool
 * Author: xiaojianbang
 * Project: xiaojianbang-stealth-hook
 *
 * Usage:
 *   xiaojianbang_hook --pid <pid> --so <name> --offset <hex>[,<hex>...] [options]
 *
 * Default behaviour: hooks the given offset(s) on ALL threads of the target
 * process (plus auto-registers new threads), then enters a live polling loop
 * that prints every new hit (args + pointer memory dump) until Ctrl+C.
 *
 * Options:
 *   --offset H[,H..]   One or more SO-relative offsets (repeatable / comma list)
 *   --dump-size N      Bytes to dump per pointer arg (default 80, max 128)
 *   --no-dump          Do not dump pointer memory, show register values only
 *   --once             Capture first hit then exit (no live loop)
 *   --listen-ret       Also capture return value via state-machine jump
 *   --modify-arg N=VAL Override register XN with VAL on entry (repeatable)
 *   --replace-ret VAL  Skip function, return VAL directly
 *   --nth N            Capture the Nth hit (skip first N-1)
 *   --query            One-shot query of current captured data, then exit
 *   --unhook           Remove all HWBPs for the offset(s), then exit
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SH_SYSCALL_MAGIC    0x584A42
#define SH_CMD_STATUS       0x0001
#define SH_CMD_HWBP_HOOK    0x1001
#define SH_CMD_HWBP_UNHOOK  0x1002
#define SH_CMD_HWBP_QUERY   0x1006
#define SH_CMD_HWBP_AUTO_THREAD 0x1007
#define SH_CMD_HWBP_SET_OVERRIDE 0x1009
#define SH_CMD_HWBP_SET_SKIP    0x100C

#define SH_HWBP_FLAG_EXECUTE    (1 << 0)
#define SH_HWBP_FLAG_LISTEN_RET (1 << 3)
#define SH_HWBP_FLAG_MODIFY_ARGS (1 << 7)
#define SH_HWBP_FLAG_SKIP_ORIGIN (1 << 8)
#define SH_STATUS_MAGIC 0x53484F4B
#define SH_VERSION_CODE 0x00010000

#define SH_DUMP_MAX     128
#define MAX_OFFSETS     16
#define MAX_TIDS        512
#define MAX_SEEN        2048

struct sh_hwbp_request {
    uint64_t target_addr;
    uint32_t target_pid;
    uint32_t flags;
    uint64_t callback_addr;
    uint64_t trampoline_addr;
    uint32_t dump_size;
    uint32_t _pad;
};

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
    uint64_t entry_args[8];
    uint64_t ret_x0;
    uint64_t entry_lr;
    uint8_t  mem_dump[8][SH_DUMP_MAX];
    uint16_t mem_len[8];
    uint32_t node_index;
    uint32_t node_total;
};

struct sh_hwbp_override {
    uint64_t target_addr;
    uint32_t target_pid;
    uint32_t flags;
    uint64_t override_mask;
    uint64_t override_args[8];
    uint64_t ret_value;
};

static long sh_call(long cmd, long a1, long a2, long a3, long a4) {
    return syscall(285, SH_SYSCALL_MAGIC, cmd, a1, a2, a3, a4);
}

/* ---- live-trace dedup table: (addr,tid) -> last seen hit_count ---- */
struct seen_entry { uint64_t addr; uint32_t tid; uint32_t last_hit; };
static struct seen_entry g_seen[MAX_SEEN];
static int g_seen_count = 0;

static uint32_t seen_get(uint64_t addr, uint32_t tid) {
    for (int i = 0; i < g_seen_count; i++)
        if (g_seen[i].addr == addr && g_seen[i].tid == tid)
            return g_seen[i].last_hit;
    return 0;
}
static void seen_set(uint64_t addr, uint32_t tid, uint32_t hit) {
    for (int i = 0; i < g_seen_count; i++)
        if (g_seen[i].addr == addr && g_seen[i].tid == tid) {
            g_seen[i].last_hit = hit;
            return;
        }
    if (g_seen_count < MAX_SEEN) {
        g_seen[g_seen_count].addr = addr;
        g_seen[g_seen_count].tid = tid;
        g_seen[g_seen_count].last_hit = hit;
        g_seen_count++;
    }
}

static volatile int g_running = 1;
static void on_sigint(int sig) { (void)sig; g_running = 0; }

static uint64_t resolve_so_base(uint32_t pid, const char *so_name) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    uint64_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, so_name)) continue;
        if (strstr(line, "r-xp") || strstr(line, "rwxp")) {
            uint64_t addr_start = strtoull(line, NULL, 16);
            char *p = strchr(line, ' ');
            if (p) p = strchr(p + 1, ' ');
            uint64_t file_offset = 0;
            if (p) file_offset = strtoull(p + 1, NULL, 16);
            base = addr_start - file_offset;
            break;
        }
    }
    fclose(f);
    return base;
}

static int get_tids(uint32_t pid, uint32_t *tids, int max_tids) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ls /proc/%u/task 2>/dev/null", pid);
    FILE *p = popen(cmd, "r");
    if (!p) return 0;
    int count = 0;
    char buf[32];
    while (fgets(buf, sizeof(buf), p) && count < max_tids)
        tids[count++] = (uint32_t)strtoul(buf, NULL, 10);
    pclose(p);
    return count;
}

/* Print one hit: registers + hex dump of pointer args */
static void print_hit(uint64_t offset, struct sh_hwbp_query *q, int do_listen_ret) {
    printf("\n[0x%llx #%u] tid=%u  pc=0x%llx\n",
           (unsigned long long)offset, q->hit_count, q->tid,
           (unsigned long long)q->last_pc);
    for (int i = 0; i < 8; i++) {
        uint64_t v = q->entry_args[i];
        if (q->mem_len[i] == 0) {
            printf("  X%d=0x%llx\n", i, (unsigned long long)v);
            continue;
        }
        printf("  X%d=0x%llx →\n", i, (unsigned long long)v);
        uint16_t n = q->mem_len[i];
        for (uint16_t off = 0; off < n; off += 16) {
            printf("      %04x: ", off);
            uint16_t row = (n - off < 16) ? (n - off) : 16;
            for (uint16_t j = 0; j < 16; j++) {
                if (j < row) printf("%02x ", q->mem_dump[i][off + j]);
                else printf("   ");
                if (j == 7) printf(" ");
            }
            printf(" |");
            for (uint16_t j = 0; j < row; j++) {
                uint8_t c = q->mem_dump[i][off + j];
                printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
            }
            printf("|\n");
        }
    }
    if (do_listen_ret)
        printf("  RET=0x%llx\n", (unsigned long long)q->ret_x0);
    fflush(stdout);
}

static void usage(void) {
    printf("xiaojianbang_hook — Zero-trace stealth hook tool\n\n");
    printf("Usage:\n");
    printf("  xiaojianbang_hook --pid <pid> --so <name> --offset <hex>[,<hex>...] [options]\n\n");
    printf("Default: hook offset(s) on ALL threads + new threads, then live-trace.\n\n");
    printf("Options:\n");
    printf("  --offset H[,H..]   SO-relative offset(s), repeatable or comma-list\n");
    printf("  --dump-size N      Bytes to dump per pointer arg (default 80, max 128)\n");
    printf("  --no-dump          Show register values only, no memory dump\n");
    printf("  --once             Capture first hit then exit\n");
    printf("  --listen-ret       Also capture return value\n");
    printf("  --modify-arg N=VAL Override register XN with VAL on entry\n");
    printf("  --replace-ret VAL  Skip function, return VAL directly\n");
    printf("  --nth N            Capture the Nth hit (skip first N-1)\n");
    printf("  --query            One-shot query of current data, then exit\n");
    printf("  --unhook           Remove all HWBPs for the offset(s), then exit\n\n");
    printf("Examples:\n");
    printf("  xiaojianbang_hook --pid 5948 --so libwtf.so --offset 0x4161c\n");
    printf("  xiaojianbang_hook --pid 5948 --so libwtf.so --offset 0x41a90,0x41d7c --dump-size 64\n");
    printf("  xiaojianbang_hook --pid 5948 --so libwtf.so --offset 0x4161c --replace-ret 0x1234\n");
    printf("  xiaojianbang_hook --pid 5948 --so libwtf.so --offset 0x4161c --unhook\n");
}

int main(int argc, char **argv)
{
    uint32_t pid = 0;
    const char *so_name = NULL;
    uint64_t offsets[MAX_OFFSETS];
    int offset_count = 0;
    int do_listen_ret = 0, do_unhook = 0, do_query = 0, do_once = 0;
    int do_replace_ret = 0, do_modify_arg = 0;
    uint64_t replace_ret_val = 0;
    uint64_t override_mask = 0;
    uint64_t override_args[8] = {0};
    uint32_t dump_size = 80;
    uint32_t nth_hit = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i+1 < argc) pid = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--so") && i+1 < argc) so_name = argv[++i];
        else if (!strcmp(argv[i], "--offset") && i+1 < argc) {
            char *arg = argv[++i];
            while (*arg && offset_count < MAX_OFFSETS) {
                offsets[offset_count++] = strtoull(arg, NULL, 0);
                char *comma = strchr(arg, ',');
                if (!comma) break;
                arg = comma + 1;
            }
        }
        else if (!strcmp(argv[i], "--listen-ret")) do_listen_ret = 1;
        else if (!strcmp(argv[i], "--unhook")) do_unhook = 1;
        else if (!strcmp(argv[i], "--query")) do_query = 1;
        else if (!strcmp(argv[i], "--once")) do_once = 1;
        else if (!strcmp(argv[i], "--no-dump")) dump_size = 0;
        else if (!strcmp(argv[i], "--dump-size") && i+1 < argc) {
            dump_size = (uint32_t)strtoul(argv[++i], NULL, 0);
            if (dump_size > SH_DUMP_MAX) dump_size = SH_DUMP_MAX;
        }
        else if (!strcmp(argv[i], "--replace-ret") && i+1 < argc) {
            do_replace_ret = 1;
            replace_ret_val = strtoull(argv[++i], NULL, 0);
        }
        else if (!strcmp(argv[i], "--modify-arg") && i+1 < argc) {
            char *arg = argv[++i];
            char *eq = strchr(arg, '=');
            if (!eq) { fprintf(stderr, "[-] --modify-arg format: N=VALUE\n"); return 1; }
            int idx = atoi(arg);
            if (idx < 0 || idx > 7) { fprintf(stderr, "[-] arg index must be 0-7\n"); return 1; }
            override_args[idx] = strtoull(eq + 1, NULL, 0);
            override_mask |= (1ULL << idx);
            do_modify_arg = 1;
        }
        else if (!strcmp(argv[i], "--nth") && i+1 < argc) {
            nth_hit = (uint32_t)strtoul(argv[++i], NULL, 0);
        }
    }

    if (!pid || !so_name || offset_count == 0) { usage(); return 1; }

    /* ARM64 hardware limit: max 6 execution breakpoints per thread.
     * Each offset consumes one breakpoint slot on every thread, so hooking
     * more than 6 offsets at once will make later registrations fail (-ENOSPC). */
    if (offset_count > 6) {
        fprintf(stderr,
            "[!] WARNING: %d offsets requested, but ARM64 allows only 6 HW "
            "execution breakpoints per thread.\n"
            "[!]          Offsets beyond the 6th will fail to register (-ENOSPC).\n"
            "[!]          Reduce to <=6 offsets, or split across multiple runs.\n",
            offset_count);
    }

    if (sh_call(SH_CMD_STATUS, 0, 0, 0, 0) != (long)(SH_STATUS_MAGIC + SH_VERSION_CODE)) {
        fprintf(stderr, "[-] KPM not active\n"); return 1;
    }

    uint64_t so_base = resolve_so_base(pid, so_name);
    if (!so_base) { fprintf(stderr, "[-] %s not found in pid %u\n", so_name, pid); return 1; }

    uint64_t targets[MAX_OFFSETS];
    for (int k = 0; k < offset_count; k++)
        targets[k] = so_base + offsets[k];
    printf("[+] %s base=0x%llx, %d offset(s)\n", so_name,
           (unsigned long long)so_base, offset_count);

    uint32_t tids[MAX_TIDS];
    int tid_count = get_tids(pid, tids, MAX_TIDS);
    if (tid_count == 0) { fprintf(stderr, "[-] no threads for pid %u\n", pid); return 1; }

    /* ---- UNHOOK: remove every (offset x tid) node, then exit ---- */
    if (do_unhook) {
        int n = 0;
        for (int k = 0; k < offset_count; k++)
            for (int t = 0; t < tid_count; t++)
                if (sh_call(SH_CMD_HWBP_UNHOOK, (long)targets[k], (long)tids[t], 0, 0) == 0) n++;
        printf("[+] unhooked %d nodes (%d offsets x %d threads)\n", n, offset_count, tid_count);
        return 0;
    }

    /* ---- QUERY: one-shot dump of all matching nodes, then exit ---- */
    if (do_query) {
        for (int k = 0; k < offset_count; k++) {
            struct sh_hwbp_query q0 = {0};
            q0.target_addr = targets[k];
            q0.node_index = 0;
            if (sh_call(SH_CMD_HWBP_QUERY, (long)&q0, 0, 0, 0) != 0) continue;
            uint32_t total = q0.node_total;
            for (uint32_t idx = 0; idx < total; idx++) {
                struct sh_hwbp_query q = {0};
                q.target_addr = targets[k];
                q.node_index = idx;
                if (sh_call(SH_CMD_HWBP_QUERY, (long)&q, 0, 0, 0) != 0) continue;
                if (q.hit_count > 0)
                    print_hit(offsets[k], &q, do_listen_ret);
            }
        }
        return 0;
    }

    /* ---- SET HOOK on every thread + auto-register new threads ---- */
    uint32_t flags = SH_HWBP_FLAG_EXECUTE;
    if (do_listen_ret) flags |= SH_HWBP_FLAG_LISTEN_RET;

    int set_total = 0;
    for (int k = 0; k < offset_count; k++) {
        for (int t = 0; t < tid_count; t++) {
            struct sh_hwbp_request req = {0};
            req.target_addr = targets[k];
            req.target_pid = tids[t];
            req.flags = flags;
            req.dump_size = dump_size;
            if (sh_call(SH_CMD_HWBP_HOOK, (long)&req, 0, 0, 0) == 0) set_total++;
        }
        /* auto-register the same hook on threads spawned later */
        sh_call(SH_CMD_HWBP_AUTO_THREAD, (long)targets[k], (long)pid, 0, (long)flags);

        /* per-offset overrides / skip count */
        if (do_replace_ret || do_modify_arg) {
            struct sh_hwbp_override ov = {0};
            ov.target_addr = targets[k];
            ov.target_pid = pid;
            if (do_modify_arg) {
                ov.flags |= SH_HWBP_FLAG_MODIFY_ARGS;
                ov.override_mask = override_mask;
                for (int i = 0; i < 8; i++) ov.override_args[i] = override_args[i];
            }
            if (do_replace_ret) {
                ov.flags |= SH_HWBP_FLAG_SKIP_ORIGIN;
                ov.ret_value = replace_ret_val;
            }
            sh_call(SH_CMD_HWBP_SET_OVERRIDE, (long)&ov, 0, 0, 0);
        }
        if (nth_hit > 0)
            sh_call(SH_CMD_HWBP_SET_SKIP, (long)targets[k], (long)(nth_hit - 1), 0, 0);
    }
    printf("[+] HWBP set: %d nodes (%d offsets x %d threads), dump_size=%u, flags=0x%x\n",
           set_total, offset_count, tid_count, dump_size, flags);

    /* If only modifying args / replacing return, no need to live-trace */
    if (do_replace_ret || do_modify_arg) {
        printf("[+] override active; not entering trace loop\n");
        return 0;
    }

    /* ---- LIVE TRACE LOOP: poll every node, print new hits until Ctrl+C ---- */
    signal(SIGINT, on_sigint);
    printf("[*] live trace started, press Ctrl+C to stop & unhook...\n");
    fflush(stdout);

    while (g_running) {
        for (int k = 0; k < offset_count; k++) {
            struct sh_hwbp_query q0 = {0};
            q0.target_addr = targets[k];
            q0.node_index = 0;
            if (sh_call(SH_CMD_HWBP_QUERY, (long)&q0, 0, 0, 0) != 0) continue;
            uint32_t total = q0.node_total;
            for (uint32_t idx = 0; idx < total; idx++) {
                struct sh_hwbp_query q = {0};
                q.target_addr = targets[k];
                q.node_index = idx;
                if (sh_call(SH_CMD_HWBP_QUERY, (long)&q, 0, 0, 0) != 0) continue;
                if (q.hit_count == 0) continue;
                if (q.hit_count != seen_get(targets[k], q.tid)) {
                    seen_set(targets[k], q.tid, q.hit_count);
                    print_hit(offsets[k], &q, do_listen_ret);
                    if (do_once) { g_running = 0; break; }
                }
            }
            if (!g_running) break;
        }
        if (g_running) usleep(50000);  /* 50ms */
    }

    /* cleanup: unhook everything we set */
    printf("\n[*] stopping, unhooking...\n");
    int n = 0;
    for (int k = 0; k < offset_count; k++)
        for (int t = 0; t < tid_count; t++)
            if (sh_call(SH_CMD_HWBP_UNHOOK, (long)targets[k], (long)tids[t], 0, 0) == 0) n++;
    printf("[+] unhooked %d nodes\n", n);
    return 0;
}

