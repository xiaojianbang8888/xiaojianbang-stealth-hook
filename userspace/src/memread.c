/* memread - read bytes from /proc/pid/mem at given address */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: memread <pid> <addr_hex> [len]\n");
        return 1;
    }
    int pid = atoi(argv[1]);
    uint64_t addr = strtoull(argv[2], NULL, 0);
    int len = argc > 3 ? atoi(argv[3]) : 128;
    if (len > 4096) len = 4096;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    if (lseek64(fd, (off64_t)addr, SEEK_SET) == (off64_t)-1) {
        perror("lseek64"); close(fd); return 1;
    }

    unsigned char buf[4096];
    int n = read(fd, buf, len);
    close(fd);
    if (n <= 0) { perror("read"); return 1; }

    /* Print as string (stop at null) */
    printf("[str] ");
    for (int i = 0; i < n && buf[i]; i++)
        putchar(buf[i] >= 32 && buf[i] < 127 ? buf[i] : '.');
    printf("\n");

    /* Print hex */
    printf("[hex] ");
    for (int i = 0; i < n && i < 64; i++)
        printf("%02x", buf[i]);
    printf("\n");

    return 0;
}
