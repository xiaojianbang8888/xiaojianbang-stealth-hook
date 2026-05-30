/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stealth Hook - User-space Control Program
 * Communicates with stealth-hook.kpm via hooked syscall #285
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

/* Include shared header (subset needed for user-space) */
#define SH_SYSCALL_MAGIC    0x584A42
#define SH_CMD_STATUS              0x0001
#define SH_STATUS_MAGIC            0x53484F4B
#define SH_VERSION_CODE            0x00010000
#define SH_CMD_HWBP_HOOK           0x1001
#define SH_CMD_HWBP_UNHOOK         0x1002
#define SH_CMD_HWBP_ENABLE         0x1003
#define SH_CMD_HWBP_DISABLE        0x1004
#define SH_CMD_HWBP_QUERY          0x1006
#define SH_CMD_PTE_HOOK            0x2001
#define SH_CMD_PTE_UNHOOK          0x2002
#define SH_CMD_PTE_COMMIT_DBI      0x2003
#define SH_CMD_GHOST_ALLOC         0x3001
#define SH_CMD_GHOST_FREE          0x3002
#define SH_CMD_GHOST_WRITE         0x3003
#define SH_CMD_MAPS_HIDE_ADD       0x4001
#define SH_CMD_MAPS_HIDE_REMOVE    0x4002
#define SH_CMD_PTRACE_SPOOF_ENABLE  0x5001
#define SH_CMD_PTRACE_SPOOF_DISABLE 0x5002

#define SH_HWBP_FLAG_EXECUTE    (1 << 0)
#define SH_HWBP_FLAG_LISTEN_RET (1 << 3)
#define SH_HWBP_FLAG_INLINE     (1 << 4)
#define SH_PROT_READ    (1 << 0)
#define SH_PROT_WRITE   (1 << 1)
#define SH_PROT_EXEC    (1 << 2)
#define SH_PAGE_SIZE    4096
#define SH_INSN_PER_PAGE (SH_PAGE_SIZE / 4)

/* Structures matching kernel definitions */
struct sh_hwbp_request {
    uint64_t target_addr;
    uint32_t target_pid;
    uint32_t flags;
    uint64_t callback_addr;
    uint64_t trampoline_addr;
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
};

struct sh_ghost_request {
    uint64_t target_va;
    uint64_t size;
    uint32_t target_pid;
    uint32_t prot;
};

struct sh_ghost_write_request {
    uint64_t target_va;
    uint64_t src_data;
    uint64_t size;
    uint32_t target_pid;
};

struct sh_maps_hide_request {
    uint64_t addr_start;
    uint64_t addr_end;
    uint32_t target_pid;
    char name[64];
};

struct sh_pte_request {
    uint64_t orig_page_addr;
    uint64_t recomp_page_addr;
    uint32_t target_pid;
    uint32_t offset_map[SH_INSN_PER_PAGE];
};

/* ============================================================
 * Syscall bridge: send command to KPM
 * ============================================================ */
static long sh_call(long cmd, long arg1, long arg2, long arg3, long arg4)
{
    return syscall(285, SH_SYSCALL_MAGIC, cmd, arg1, arg2, arg3, arg4);
}

/* ============================================================
 * High-level API wrappers
 * ============================================================ */

static long sh_status(void)
{
    return sh_call(SH_CMD_STATUS, 0, 0, 0, 0);
}

/* Allocate ghost memory - direct args (no struct pointer, avoids PAN) */
static long sh_ghost_alloc(uint64_t va, uint64_t size, uint32_t pid, uint32_t prot)
{
    return sh_call(SH_CMD_GHOST_ALLOC, (long)va, (long)size, (long)pid, (long)prot);
}

static long sh_ghost_write(uint64_t va, void *data, uint64_t size, uint32_t pid)
{
    struct sh_ghost_write_request req = {
        .target_va = va,
        .src_data = (uint64_t)data,
        .size = size,
        .target_pid = pid,
    };
    return sh_call(SH_CMD_GHOST_WRITE, (long)&req, 0, 0, 0);
}

static long sh_ghost_free(uint64_t va, uint32_t pid)
{
    return sh_call(SH_CMD_GHOST_FREE, (long)va, (long)pid, 0, 0);
}

/* Set hardware breakpoint */
static long sh_hwbp_hook(uint64_t addr, uint32_t pid, uint32_t flags)
{
    struct sh_hwbp_request req = {
        .target_addr = addr,
        .target_pid = pid,
        .flags = flags,
    };
    return sh_call(SH_CMD_HWBP_HOOK, (long)&req, 0, 0, 0);
}

static long sh_hwbp_unhook(uint64_t addr, uint32_t tid)
{
    return sh_call(SH_CMD_HWBP_UNHOOK, (long)addr, (long)tid, 0, 0);
}

static long sh_hwbp_enable(uint64_t addr, uint32_t tid)
{
    return sh_call(SH_CMD_HWBP_ENABLE, (long)addr, (long)tid, 0, 0);
}

static long sh_hwbp_disable(uint64_t addr, uint32_t tid)
{
    return sh_call(SH_CMD_HWBP_DISABLE, (long)addr, (long)tid, 0, 0);
}

static long sh_hwbp_query(uint64_t addr, uint32_t tid)
{
    struct sh_hwbp_query q = { .target_addr = addr, .tid = tid };
    long ret = sh_call(SH_CMD_HWBP_QUERY, (long)&q, 0, 0, 0);
    if (ret == 0) {
        printf("[*] hit_count=%u last_pc=0x%llx x0=0x%llx x1=0x%llx x2=0x%llx disabled=%u waiting_ret=%u\n",
               q.hit_count, (unsigned long long)q.last_pc,
               (unsigned long long)q.last_x0, (unsigned long long)q.last_x1,
               (unsigned long long)0ULL, q.is_disabled, q.is_waiting_return);
    }
    return ret;
}

/* Hide memory region from maps */
static long sh_maps_hide(uint64_t start, uint64_t end, uint32_t pid, const char *name)
{
    struct sh_maps_hide_request req = {
        .addr_start = start,
        .addr_end = end,
        .target_pid = pid,
    };
    if (name) strncpy(req.name, name, 63);
    return sh_call(SH_CMD_MAPS_HIDE_ADD, (long)&req, 0, 0, 0);
}

static long sh_maps_hide_remove(uint64_t start, uint32_t pid)
{
    return sh_call(SH_CMD_MAPS_HIDE_REMOVE, (long)start, (long)pid, 0, 0);
}

/* Enable ptrace spoofing for a process */
static long sh_ptrace_spoof(uint32_t pid)
{
    return sh_call(SH_CMD_PTRACE_SPOOF_ENABLE, (long)pid, 0, 0, 0);
}

static long sh_ptrace_spoof_disable(uint32_t pid)
{
    return sh_call(SH_CMD_PTRACE_SPOOF_DISABLE, (long)pid, 0, 0, 0);
}

/* ============================================================
 * CLI interface
 * ============================================================ */
static void usage(const char *prog)
{
    printf("Stealth Hook Control - User-space interface\n");
    printf("Usage: %s <command> [args...]\n\n", prog);
    printf("Commands:\n");
    printf("  status                    Check if KPM is loaded\n");
    printf("  ghost <va> <size> <pid>   Allocate ghost memory\n");
    printf("  ghostfree <va> <pid>      Free ghost memory\n");
    printf("  ghostwrite <va> <pid> <text>  Write text to ghost memory\n");
    printf("  hwbp <addr> <tid>         Set hardware breakpoint (observer)\n");
    printf("  hwbp_unhook <addr> <tid>  Remove hardware breakpoint\n");
    printf("  hwbp_enable <addr> <tid>  Enable hardware breakpoint\n");
    printf("  hwbp_disable <addr> <tid> Disable hardware breakpoint\n");
    printf("  hwbp_query <addr> <tid>   Query hardware breakpoint hit info\n");
    printf("  hide <start> <end> <pid>  Hide memory range from maps\n");
    printf("  hideremove <start> <pid>  Remove maps hide range\n");
    printf("  hidename <name> <pid>     Hide maps entries by name\n");
    printf("  spoof <pid>               Enable ptrace spoofing (0 = global test mode)\n");
    printf("  spoof_for <ms>            Enable global ptrace spoofing briefly\n");
    printf("  spoof_disable <pid>       Disable ptrace spoofing\n");
    printf("\nAll addresses in hex (0x prefix optional)\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "status") == 0) {
        printf("[*] Testing KPM connection via syscall #285...\n");
        long ret = sh_status();
        printf("[*] syscall returned: %ld (0x%lx)\n", ret, ret);
        if (ret == ((long)SH_STATUS_MAGIC + SH_VERSION_CODE)) {
            printf("[+] KPM is ACTIVE (version 1.0.0)\n");
            return 0;
        }
        printf("[-] KPM is not responding with expected status magic\n");
        return 1;
    }

    if (strcmp(cmd, "ghost") == 0 && argc >= 5) {
        uint64_t va = strtoull(argv[2], NULL, 0);
        uint64_t size = strtoull(argv[3], NULL, 0);
        uint32_t pid = (uint32_t)strtoul(argv[4], NULL, 0);
        printf("[*] Allocating ghost memory: va=0x%llx size=0x%llx pid=%d\n",
               (unsigned long long)va, (unsigned long long)size, pid);
        long ret = sh_ghost_alloc(va, size, pid, SH_PROT_READ | SH_PROT_WRITE | SH_PROT_EXEC);
        printf("[*] Result: %ld (0x%lx)\n", ret, ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "ghostfree") == 0 && argc >= 4) {
        uint64_t va = strtoull(argv[2], NULL, 0);
        uint32_t pid = (uint32_t)strtoul(argv[3], NULL, 0);
        printf("[*] Freeing ghost memory: va=0x%llx pid=%d\n",
               (unsigned long long)va, pid);
        long ret = sh_ghost_free(va, pid);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "ghostwrite") == 0 && argc >= 5) {
        uint64_t va = strtoull(argv[2], NULL, 0);
        uint32_t pid = (uint32_t)strtoul(argv[3], NULL, 0);
        const char *text = argv[4];
        long ret = sh_ghost_write(va, (void *)text, strlen(text) + 1, pid);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "hwbp") == 0 && argc >= 4) {
        uint64_t addr = strtoull(argv[2], NULL, 0);
        uint32_t tid = (uint32_t)strtoul(argv[3], NULL, 0);
        printf("[*] Setting HWBP: addr=0x%llx tid=%d (observer+listen_ret)\n",
               (unsigned long long)addr, tid);
        long ret = sh_hwbp_hook(addr, tid, SH_HWBP_FLAG_EXECUTE | SH_HWBP_FLAG_LISTEN_RET);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "hwbp_unhook") == 0 && argc >= 4) {
        uint64_t addr = strtoull(argv[2], NULL, 0);
        uint32_t tid = (uint32_t)strtoul(argv[3], NULL, 0);
        printf("[*] Removing HWBP: addr=0x%llx tid=%d\n",
               (unsigned long long)addr, tid);
        long ret = sh_hwbp_unhook(addr, tid);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "hwbp_enable") == 0 && argc >= 4) {
        uint64_t addr = strtoull(argv[2], NULL, 0);
        uint32_t tid = (uint32_t)strtoul(argv[3], NULL, 0);
        printf("[*] Enabling HWBP: addr=0x%llx tid=%d\n",
               (unsigned long long)addr, tid);
        long ret = sh_hwbp_enable(addr, tid);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "hwbp_disable") == 0 && argc >= 4) {
        uint64_t addr = strtoull(argv[2], NULL, 0);
        uint32_t tid = (uint32_t)strtoul(argv[3], NULL, 0);
        printf("[*] Disabling HWBP: addr=0x%llx tid=%d\n",
               (unsigned long long)addr, tid);
        long ret = sh_hwbp_disable(addr, tid);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "hwbp_query") == 0 && argc >= 4) {
        uint64_t addr = strtoull(argv[2], NULL, 0);
        uint32_t tid = (uint32_t)strtoul(argv[3], NULL, 0);
        long ret = sh_hwbp_query(addr, tid);
        printf("[*] query ret: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "hide") == 0 && argc >= 5) {
        uint64_t start = strtoull(argv[2], NULL, 0);
        uint64_t end = strtoull(argv[3], NULL, 0);
        uint32_t pid = (uint32_t)strtoul(argv[4], NULL, 0);
        printf("[*] Hiding maps range: 0x%llx-0x%llx pid=%d\n",
               (unsigned long long)start, (unsigned long long)end, pid);
        long ret = sh_maps_hide(start, end, pid, NULL);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "hideremove") == 0 && argc >= 4) {
        uint64_t start = strtoull(argv[2], NULL, 0);
        uint32_t pid = (uint32_t)strtoul(argv[3], NULL, 0);
        printf("[*] Removing maps hide range: 0x%llx pid=%d\n",
               (unsigned long long)start, pid);
        long ret = sh_maps_hide_remove(start, pid);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "hidename") == 0 && argc >= 4) {
        const char *name = argv[2];
        uint32_t pid = (uint32_t)strtoul(argv[3], NULL, 0);
        printf("[*] Hiding maps by name: \"%s\" pid=%d\n", name, pid);
        long ret = sh_maps_hide(0, 0, pid, name);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "spoof") == 0 && argc >= 3) {
        uint32_t pid = (uint32_t)strtoul(argv[2], NULL, 0);
        if (pid == 0)
            printf("[*] Enabling ptrace spoof global test mode\n");
        else
            printf("[*] Enabling ptrace spoof for pid=%d\n", pid);
        long ret = sh_ptrace_spoof(pid);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "spoof_for") == 0 && argc >= 3) {
        unsigned long ms = strtoul(argv[2], NULL, 0);
        if (ms == 0) {
            printf("[-] Duration must be greater than 0 ms\n");
            return 1;
        }
        if (ms > 60000) {
            printf("[-] Duration too long; max is 60000 ms\n");
            return 1;
        }
        printf("[*] Enabling ptrace spoof global test mode for %lu ms\n", ms);
        long ret = sh_ptrace_spoof(0);
        printf("[*] Enable result: %ld\n", ret);
        if (ret < 0)
            return 1;
        usleep(ms * 1000);
        ret = sh_ptrace_spoof_disable(0);
        printf("[*] Disable result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "spoof_disable") == 0 && argc >= 3) {
        uint32_t pid = (uint32_t)strtoul(argv[2], NULL, 0);
        if (pid == 0)
            printf("[*] Disabling ptrace spoof global test mode\n");
        else
            printf("[*] Disabling ptrace spoof for pid=%d\n", pid);
        long ret = sh_ptrace_spoof_disable(pid);
        printf("[*] Result: %ld\n", ret);
        return ret < 0 ? 1 : 0;
    }

    usage(argv[0]);
    return 1;
}
