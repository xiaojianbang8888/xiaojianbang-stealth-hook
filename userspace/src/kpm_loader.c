/* KPM loader - loads/unloads xiaojianbang-stealth-hook.kpm via KernelPatch supercall
 * Based on KernelPatch/user/supercall.h interface */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_supercall 45

#define SUPERCALL_HELLO      0x1000
#define SUPERCALL_HELLO_MAGIC 0x11581158
#define SUPERCALL_KPM_LOAD   0x1020
#define SUPERCALL_KPM_UNLOAD 0x1021
#define SUPERCALL_KPM_CONTROL 0x1022
#define SUPERCALL_KPM_NUMS   0x1030
#define SUPERCALL_KPM_LIST   0x1031
#define SUPERCALL_KPM_INFO   0x1032

/* Must match the version used when patching boot (KP 0.13.1 = 0x0D01) */
#define MAJOR 0
#define MINOR 13
#define PATCH 1

static inline long ver_and_cmd(const char *key, long cmd)
{
    (void)key;
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return ((long)version_code << 32) | (0x1158 << 16) | (cmd & 0xFFFF);
}

static const char *SUPERKEY = "xiaojianbang8888";

static long sc_hello(void)
{
    return syscall(__NR_supercall, SUPERKEY, ver_and_cmd(SUPERKEY, SUPERCALL_HELLO));
}

static long sc_kpm_load(const char *path, const char *args)
{
    return syscall(__NR_supercall, SUPERKEY, ver_and_cmd(SUPERKEY, SUPERCALL_KPM_LOAD),
                   path, args, NULL);
}

static long sc_kpm_unload(const char *name)
{
    return syscall(__NR_supercall, SUPERKEY, ver_and_cmd(SUPERKEY, SUPERCALL_KPM_UNLOAD),
                   name, NULL);
}

static long sc_kpm_nums(void)
{
    return syscall(__NR_supercall, SUPERKEY, ver_and_cmd(SUPERKEY, SUPERCALL_KPM_NUMS));
}

static long sc_kpm_list(char *buf, int buf_len)
{
    return syscall(__NR_supercall, SUPERKEY, ver_and_cmd(SUPERKEY, SUPERCALL_KPM_LIST),
                   buf, buf_len);
}

static long sc_kpm_info(const char *name, char *buf, int buf_len)
{
    return syscall(__NR_supercall, SUPERKEY, ver_and_cmd(SUPERKEY, SUPERCALL_KPM_INFO),
                   name, buf, buf_len);
}

static long sc_kpm_control(const char *name, const char *args, char *out, long outlen)
{
    return syscall(__NR_supercall, SUPERKEY, ver_and_cmd(SUPERKEY, SUPERCALL_KPM_CONTROL),
                   name, args, out, outlen);
}

static void usage(void)
{
    printf("kpm_loader — KPM dynamic load/unload via supercall\n\n");
    printf("Usage:\n");
    printf("  kpm_loader hello              Test supercall connection\n");
    printf("  kpm_loader list               List loaded KPMs\n");
    printf("  kpm_loader info <name>        Show KPM info\n");
    printf("  kpm_loader load <path> [args] Load KPM from file\n");
    printf("  kpm_loader unload <name>      Unload KPM by name\n");
    printf("  kpm_loader reload <path>      Unload 'xiaojianbang-stealth-hook' then load from path\n");
    printf("  kpm_loader control <name> <args>  Send control command\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(); return 1; }

    const char *action = argv[1];

    /* hello */
    if (strcmp(action, "hello") == 0) {
        long ret = sc_hello();
        printf("[*] supercall hello: 0x%lx (expect 0x%x)\n", ret, SUPERCALL_HELLO_MAGIC);
        if (ret == SUPERCALL_HELLO_MAGIC) {
            printf("[+] KernelPatch is active\n");
            return 0;
        } else {
            printf("[-] KernelPatch not active or superkey wrong\n");
            return 1;
        }
    }

    /* Verify KP is active for all other commands */
    if (sc_hello() != SUPERCALL_HELLO_MAGIC) {
        printf("[-] KernelPatch not active\n");
        return 1;
    }

    /* list */
    if (strcmp(action, "list") == 0) {
        long nums = sc_kpm_nums();
        printf("[*] loaded KPM count: %ld\n", nums);
        if (nums > 0) {
            char buf[1024] = {0};
            long ret = sc_kpm_list(buf, sizeof(buf));
            printf("[*] sc_kpm_list ret=%ld\n", ret);
            if (ret > 0) printf("[+] modules:\n%s\n", buf);
            else printf("[-] list failed or empty\n");
        }
        return 0;
    }

    /* info */
    if (strcmp(action, "info") == 0) {
        if (argc < 3) { printf("Usage: kpm_loader info <name>\n"); return 1; }
        char buf[1024] = {0};
        long ret = sc_kpm_info(argv[2], buf, sizeof(buf));
        printf("[*] sc_kpm_info('%s') ret=%ld\n", argv[2], ret);
        if (ret > 0) printf("%s\n", buf);
        else printf("[-] info failed (ret=%ld)\n", ret);
        return ret >= 0 ? 0 : 1;
    }

    /* load */
    if (strcmp(action, "load") == 0) {
        if (argc < 3) { printf("Usage: kpm_loader load <path> [args]\n"); return 1; }
        const char *path = argv[2];
        const char *args = argc >= 4 ? argv[3] : NULL;
        printf("[*] Loading: %s (args: %s)\n", path, args ? args : "none");
        long ret = sc_kpm_load(path, args);
        printf("[*] Result: %ld\n", ret);
        if (ret == 0) printf("[+] KPM loaded successfully\n");
        else printf("[-] KPM load failed (ret=%ld)\n", ret);
        return ret == 0 ? 0 : 1;
    }

    /* unload */
    if (strcmp(action, "unload") == 0) {
        if (argc < 3) { printf("Usage: kpm_loader unload <name>\n"); return 1; }
        const char *name = argv[2];
        printf("[*] Unloading: %s\n", name);
        long ret = sc_kpm_unload(name);
        printf("[*] Result: %ld\n", ret);
        if (ret == 0) printf("[+] KPM unloaded\n");
        else printf("[-] KPM unload failed (ret=%ld)\n", ret);
        return ret == 0 ? 0 : 1;
    }

    /* reload = unload xiaojianbang-stealth-hook + load new */
    if (strcmp(action, "reload") == 0) {
        if (argc < 3) { printf("Usage: kpm_loader reload <path>\n"); return 1; }
        const char *path = argv[2];
        printf("[*] Unloading xiaojianbang-stealth-hook...\n");
        long ret = sc_kpm_unload("xiaojianbang-stealth-hook");
        printf("[*] unload ret=%ld\n", ret);
        if (ret != 0) printf("[!] unload failed, trying load anyway...\n");
        printf("[*] Loading: %s\n", path);
        ret = sc_kpm_load(path, NULL);
        printf("[*] load ret=%ld\n", ret);
        if (ret == 0) printf("[+] Reload successful\n");
        else printf("[-] Reload failed\n");
        return ret == 0 ? 0 : 1;
    }

    /* control */
    if (strcmp(action, "control") == 0) {
        if (argc < 4) { printf("Usage: kpm_loader control <name> <args>\n"); return 1; }
        char out[256] = {0};
        long ret = sc_kpm_control(argv[2], argv[3], out, sizeof(out));
        printf("[*] control ret=%ld\n", ret);
        if (out[0]) printf("[*] output: %s\n", out);
        return ret == 0 ? 0 : 1;
    }

    usage();
    return 1;
}
