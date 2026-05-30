# Stealth Hook - User-space programs Makefile
# Cross-compile for Android ARM64

ifndef TARGET_COMPILE
    TARGET_COMPILE = aarch64-linux-gnu-
endif

CC = $(TARGET_COMPILE)gcc
CFLAGS = -O2 -Wall -static -Iinclude

SRCS_CONTROL = src/sh_control.c
SRCS_DBI = src/dbi_decoder.c src/dbi_recompiler.c

all: sh_control ptrace_regset_test ghost_maps_test hwbp_observer_test perf_hwbp_baseline pte_hook_test pte_dbi_stress_test pte_callback_test hook_real_func_test xiaojianbang_hook

sh_control: $(SRCS_CONTROL)
	$(CC) $(CFLAGS) -o $@ $^

ptrace_regset_test: src/ptrace_regset_test.c
	$(CC) $(CFLAGS) -o $@ $^

ghost_maps_test: src/ghost_maps_test.c
	$(CC) $(CFLAGS) -o $@ $^

hwbp_observer_test: src/hwbp_observer_test.c
	$(CC) $(CFLAGS) -o $@ $^

perf_hwbp_baseline: src/perf_hwbp_baseline.c
	$(CC) $(CFLAGS) -o $@ $^

pte_hook_test: src/pte_hook_test.c src/dbi_decoder.c src/dbi_recompiler.c
	$(CC) $(CFLAGS) -o $@ $^

pte_dbi_stress_test: src/pte_dbi_stress_test.c src/dbi_decoder.c src/dbi_recompiler.c
	$(CC) $(CFLAGS) -o $@ $^

pte_callback_test: src/pte_callback_test.c src/dbi_decoder.c src/dbi_recompiler.c
	$(CC) $(CFLAGS) -o $@ $^

hook_real_func_test: src/hook_real_func_test.c src/dbi_decoder.c src/dbi_recompiler.c
	$(CC) $(CFLAGS) -o $@ $^

xiaojianbang_hook: src/xiaojianbang_hook.c src/dbi_decoder.c src/dbi_recompiler.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f sh_control ptrace_regset_test ghost_maps_test hwbp_observer_test perf_hwbp_baseline pte_hook_test pte_dbi_stress_test pte_callback_test hook_real_func_test xiaojianbang_hook *.o
