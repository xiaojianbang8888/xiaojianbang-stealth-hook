# xiaojianbang Stealth Hook — Android 内核无痕 Hook 框架

> 基于 KernelPatch + ARM64 硬件断点（HWBP）的零痕迹 Hook 方案。
> 不修改目标进程任何内存，不注入 SO，不创建可疑映射。
> 在最高对抗强度的反作弊环境下仍然有效。

---

## 作者

| | |
|------|------|
| 作者 | **xiaojianbang** |
| 微信 | xiaojianbang8888 |
| 官网 | https://xjbedu.site |
| B站 | https://space.bilibili.com/534838862 |
| 公众号 | 非攻code |
| 知识星球 | 小肩膀和他的朋友们 |

**平台定位：**
- **B站**：免费视频教程（爬虫、JS、Android、iOS逆向、浏览器内核）
- **公众号（非攻code）**：免费技术文章
- **知识星球（小肩膀和他的朋友们）**：可直接落地的技术方案、源码、成品工具

---

## 项目信息

| | |
|------|------|
| 项目名 | xiaojianbang-stealth-hook |
| 用户态工具 | xiaojianbang_hook |
| 内核模块 | xiaojianbang-stealth-hook.kpm |
| 技术栈 | ARM64 HWBP / PTE-UXN / DBI / KernelPatch KPM |
| License | GPL-2.0-or-later |

---

## 框架组成

使用只需要两个文件：

| 文件 | 说明 |
|------|------|
| `xiaojianbang-stealth-hook.kpm` | 内核模块，APatch App 直接加载 |
| `xiaojianbang_hook` | 用户态工具，arm64 静态链接，推到设备即用 |

---

## 实现原理

```
用户态                              内核态 (KPM by xiaojianbang)

xiaojianbang_hook ── syscall 285 ──→ stealth_hook.c dispatch
                                      │
                                      ├─ HWBP_HOOK → 对所有线程注册硬件断点
                                      ├─ AUTO_THREAD → 新线程自动覆盖
                                      ├─ SET_OVERRIDE → 配置改参/跳过
                                      ├─ QUERY → 返回 hit_count + args + mem_dump
                                      └─ UNHOOK → 释放断点

目标函数执行 ── CPU debug trap ──→ hwbp_handler()
                                      │
                                      ├─ 记录 X0-X7, LR
                                      ├─ PAN bypass dump 指针内存（hex+ascii）
                                      ├─ SKIP_ORIGIN: pc=LR, x0=ret_value
                                      ├─ MODIFY_ARGS: regs[N]=value
                                      └─ 状态机: BP跳到LR → 函数返回 → BP跳回入口
```

核心思路：利用 ARM64 CPU 的硬件调试寄存器，在内核态注册断点。目标函数执行时 CPU 自动 trap 到内核 handler，直接操作寄存器后返回用户态。全程不修改任何用户态内存。

---

## 设备要求

| 条件 | 要求 | 说明 |
|------|------|------|
| CPU | arm64 | 仅支持 ARM64 架构 |
| 内核 | 5.4+ GKI | Android GKI 内核（Google 通用内核镜像） |
| KernelPatch | 0.13.x | kpimg 版本 d01，提供 KPM 加载能力 |
| APatch | 已安装 | 用于加载 KPM 模块和提供 su 权限 |
| Bootloader | 已解锁 | APatch/KernelPatch 的前提 |

### 已验证设备

| 设备 | 系统 | 内核 |
|------|------|------|
| Pixel 6 (oriole) | Android 15 | 5.10.209 |

理论上所有满足上述条件的 arm64 GKI 设备都可以使用。

---

## 安装

```bash
# 1. 推送文件到设备
adb push xiaojianbang-stealth-hook.kpm /sdcard/
adb push xiaojianbang_hook /data/local/tmp/
adb shell "su -c 'chmod 755 /data/local/tmp/xiaojianbang_hook'"

# 2. 在 APatch App 中加载 KPM
#    打开 APatch → 模块管理 → 加载 /sdcard/xiaojianbang-stealth-hook.kpm

# 3. 验证
adb shell "su -c '/data/local/tmp/xiaojianbang_hook --pid 1 --so libc.so --offset 0x1' 2>&1"
# 看到 "[+] libc.so base=..." 即正常
```

---

## 使用方法

### 命令格式

```bash
xiaojianbang_hook --pid <pid> --so <name> --offset <hex>[,<hex>...] [选项]
```

### Live Trace（默认行为）

```bash
xiaojianbang_hook --pid $PID --so libwtf.so --offset 0x41ac0,0x41d7c --dump-size 96
```

设完 hook 后自动进入持续监听。每次函数调用实时输出 X0-X7 + 指针内存 dump（hex+ascii）。Ctrl+C 退出时自动 unhook。

输出示例：
```
[+] libwtf.so base=0x7a01a94000, 2 offset(s)
[+] HWBP set: 156 nodes (2 offsets x 78 threads), dump_size=96, flags=0x1
[*] live trace started, press Ctrl+C to stop & unhook...

[0x41ac0 #1] tid=5852  pc=0x7574482ac0
  X0=0x7ff2c3c2f0 →
      0000: 01 23 45 67 89 ab cd ef  fe dc ba 98 76 54 32 10  |.#Eg........vT2.|
  X2=0x771610cdb0 →
      0000: 31 37 38 30 30 38 35 32  37 39 31 35 36 63 39 65  |1780085279156c9e|
      0010: 62 37 38 34 31 2d 39 38  31 66 2d 34 61 39 66 2d  |b7841-981f-4a9f-|
  X4=0x40
  ...

[*] stopping, unhooking...
[+] unhooked 156 nodes
```

### 其他操作模式

```bash
# 持续监听 + 返回值
xiaojianbang_hook --pid $PID --so libwtf.so --offset 0x4161c --listen-ret

# 替换返回值（跳过原函数）
xiaojianbang_hook --pid $PID --so libc.so --offset 0x65330 --replace-ret 12345

# 修改参数
xiaojianbang_hook --pid $PID --so libwtf.so --offset 0x4161c --modify-arg 0=0x100 --modify-arg 1=0x200

# 捕获第 N 次调用
xiaojianbang_hook --pid $PID --so libwtf.so --offset 0x3e5b0 --nth 3

# 手动查询
xiaojianbang_hook --query --pid $PID --so libwtf.so --offset 0x4161c

# 卸载
xiaojianbang_hook --unhook --pid $PID --so libwtf.so --offset 0x4161c
```

---

## 完整参数列表

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--pid <pid>` | 目标进程 PID | 必选 |
| `--so <name>` | SO 库名称 | 必选 |
| `--offset <hex>[,hex...]` | 函数偏移（逗号分隔，上限 6） | 必选 |
| `--listen-ret` | 同时捕获返回值 | 不捕获 |
| `--replace-ret <val>` | 跳过原函数，返回指定值 | 不跳过 |
| `--modify-arg N=VAL` | 修改第 N 个参数（可重复，N=0~7） | 不修改 |
| `--dump-size <N>` | 每个指针 dump N 字节 | 80 |
| `--no-dump` | 不 dump 内存 | dump |
| `--nth N` | 从第 N 次触发开始输出 | 1 |
| `--once` | 只抓一次就退出 | 持续监听 |
| `--query` | 手动查询最后一次 hit | live trace |
| `--unhook` | 卸载 hook | — |

---

## 核心特性

- **全线程覆盖**：自动遍历 /proc/pid/task 对所有线程设断点 + auto_thread 监听新线程
- **多地址 hook**：逗号分隔，一次设多个断点（硬件上限 6 个）
- **持续监听**：状态机振荡（entry→LR→entry），每次调用都输出，永不停止
- **通用内存 dump**：寄存器值像指针就自动 dump hex+ascii，不猜类型
- **Ctrl+C 自动清理**：退出时 unhook 所有断点
- **动态热重载**：通过 supercall 动态加载/卸载 KPM，无需重启设备

---

## 反检测能力

| 检测手段 | Frida | Xposed | Dobby | xiaojianbang_hook |
|----------|:-----:|:------:|:-----:|:-----------------:|
| .text CRC 校验 | ❌ | ❌ | ❌ | ✅ 不修改代码 |
| /proc/maps 扫描 | ❌ | ❌ | ❌ | ✅ maps_hide |
| ptrace 读调试寄存器 | N/A | N/A | N/A | ✅ 假账本 |
| perf_event_open | N/A | N/A | N/A | ✅ 内核态不占配额 |
| 线程检测 | ❌ | ❌ | ✅ | ✅ 无线程 |
| Frida 特征 | ❌ | ✅ | ✅ | ✅ 无关 |
| TracerPid | ❌ | ✅ | ✅ | ✅ 零 |

---

## 注意事项

1. **ARM64 硬件断点上限 6 个**：每个 offset 占一个槽位，超过会 -ENOSPC
2. **不要 hook 高频通用函数**：如 memcpy、malloc。应 hook 目标函数内部的具体地址
3. **su 输出问题**：APatch su 需加 `2>&1`
4. **hit_count 爆炸 = hook 错了位置**：正常业务函数调用频率很低

---

## 目录结构

```
xiaojianbang-stealth-hook/
├── README.md                       # 本文档
├── kpm/                            # 内核模块源码
│   ├── stealth_hook.c              # syscall bridge + dispatch
│   ├── stealth_hook.h              # 命令定义 + 结构体
│   ├── hwbp.c                      # HWBP: handler/状态机/dump/override
│   ├── pte_hook.c                  # PTE/UXN hook + DBI 重定向
│   ├── ghost_mem.c                 # Ghost Memory
│   ├── maps_hide.c                 # /proc/maps 隐藏
│   ├── ptrace_spoof.c             # ptrace 假账本
│   └── Makefile
├── userspace/                      # 用户态源码
│   ├── src/xiaojianbang_hook.c     # 主工具
│   ├── src/dbi_recompiler.c        # DBI 指令重编译
│   ├── src/dbi_decoder.c           # ARM64 指令分类器
│   ├── src/kpm_loader.c            # KPM 动态加载/卸载
│   ├── src/sh_control.c            # KPM 状态检查
│   ├── src/memread.c               # /proc/pid/mem 辅助
│   ├── include/dbi.h
│   └── Makefile
└── release/                        # 发布文件（只需这两个）
    ├── xiaojianbang-stealth-hook.kpm
    └── xiaojianbang_hook
```

---

## 致谢与参考

完整的实现过程，会写成文章，放在知识星球：**小肩膀和他的朋友们**

感谢珍惜佬，原文链接：https://bbs.kanxue.com/thread-290718.htm

---

## 联系作者

有问题或建议，欢迎通过以下方式联系：

- **微信**：xiaojianbang8888
- **B站**：https://space.bilibili.com/534838862
- **公众号**：非攻code
- **知识星球**：小肩膀和他的朋友们
- **官网**：https://xjbedu.site
