ifndef KP_DIR
    KP_DIR = /home/xiaojianbang/bin/KernelPatch-main
endif

CC = /home/xiaojianbang/bin/aosp/prebuilts/clang/host/linux-x86/clang-r522817/bin/clang
CFLAGS = --target=aarch64-linux-gnu -Os -fno-stack-protector -fno-asynchronous-unwind-tables -fno-PIC -fno-plt -Wno-unused-function

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))
INCLUDE_FLAGS += -I.

objs := stealth_hook.o hwbp.o pte_hook.o ghost_mem.o maps_hide.o ptrace_spoof.o

all: xiaojianbang-stealth-hook.kpm

xiaojianbang-stealth-hook.kpm: $(objs)
	$(CC) --target=aarch64-linux-gnu -r -nostdlib -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm *.o
