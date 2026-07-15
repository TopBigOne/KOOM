/*
 * Copyright (c) 2021. Kwai, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Created by lbtrace on 2021.
 *
 */

// Implements the backtrace capture used on every hooked allocation (the hot
// path of the "record" stage). This walks the x29/frame-pointer chain
// directly instead of parsing DWARF/.eh_frame unwind tables (as a full
// libunwind-style unwinder would); this is much cheaper per call, at the
// cost of being less robust (it can be defeated by frame-pointer-omitting
// codegen or corrupted frames) — an acceptable trade-off since this runs on
// every malloc/calloc/memalign/posix_memalign call in the hooked libraries.
// 中文：本文件实现了每次被 hook 的分配调用（即“record”阶段的热路径）都要
// 用到的调用栈捕获逻辑。它直接遍历 x29 帧指针链，而不是解析 DWARF/.eh_frame
// 展开表（像完整的 libunwind 风格展开器那样）；这样每次调用的开销要低得多，
// 代价是健壮性较差（可能被省略帧指针的代码生成方式或损坏的帧破坏）——鉴于
// 这段代码运行在被 hook 库的每一次 malloc/calloc/memalign/posix_memalign
// 调用上，这个取舍是可以接受的。
#include "utils/stack_trace.h"

static const uint32_t kT32InstrLen = 2;
static const uint32_t kA32InstrLen = 4;
static const uint32_t kA64InstrLen = 4;
// TLS variables use the "initial-exec" model (see FAST_UNWIND_TLS_INITIAL_EXEC
// in stack_trace.h) to avoid the extra indirection/lazy-init overhead of the
// default "global-dynamic" TLS access model, since these are read on every
// hooked allocation.
// 中文：这些线程局部变量使用“initial-exec”模型（见 stack_trace.h 中的
// FAST_UNWIND_TLS_INITIAL_EXEC），以避免默认的“global-dynamic”TLS 访问模型
// 所带来的额外间接寻址/惰性初始化开销，因为这些变量会在每一次被 hook 的
// 分配调用中被读取。
static FAST_UNWIND_TLS_INITIAL_EXEC uintptr_t stack_top = 0;
static FAST_UNWIND_TLS_INITIAL_EXEC pthread_once_t once_control_tls =
    PTHREAD_ONCE_INIT;

/** Returns this thread's cached stack-top address, used as an unwind bound.
 *
 * 中文：返回该线程缓存的栈顶地址，作为回溯时的边界使用。
 */
inline __attribute__((__always_inline__)) uintptr_t get_thread_stack_top() {
  return stack_top;
}

// A frame-pointer-chain stack frame: the saved previous frame pointer (x29)
// followed immediately by the saved link register/return address — the
// layout the AAPCS64 calling convention produces when frame pointers are
// kept, which is what makes walking this chain by pointer-chasing possible.
// 中文：这是帧指针链中的一个栈帧：保存的上一级帧指针（x29）紧跟着保存的
// 链接寄存器/返回地址——这正是 AAPCS64 调用约定在保留帧指针时产生的内存
// 布局，正因如此才能够通过“追指针”的方式遍历这条链。
struct frame_record {
  uintptr_t next_frame, return_addr;
};

/**
 * One-time (per-thread, via pthread_once) initialization that queries this
 * thread's stack bounds via pthread_getattr_np, so FastUnwind knows where to
 * stop walking frame pointers without running off the end of the stack.
 *
 * 中文：一次性（借助 pthread_once，按每个线程执行一次）的初始化，通过
 * pthread_getattr_np 查询本线程的栈边界，使 FastUnwind 知道该在哪里停止
 * 遍历帧指针，而不会越过栈的末端。
 */
void fast_unwind_init() {
  pthread_attr_t attr;
  pthread_getattr_np(pthread_self(), &attr);
  stack_top =
      (uintptr_t)(attr.stack_size + static_cast<char *>(attr.stack_base));
}

/**
 * Adjusts a captured return address back to (approximately) the address of
 * the call instruction itself, since the return address points just past
 * the call (the instruction that would execute next), and symbolizing the
 * return address directly can attribute the frame to the wrong function/
 * line when the call is the last instruction of its source line.
 *
 * 中文：将捕获到的返回地址调整回（大致）调用指令本身的地址，因为返回地址
 * 指向的是调用指令之后的下一条指令；如果直接对返回地址做符号化，在调用
 * 指令恰好是其源码行最后一条指令的情况下，可能会把这一帧错误地归属到
 * 别的函数/行上。
 */
static inline uintptr_t GetAdjustPC(uintptr_t pc) {
// arm64/arm-only: fixed instruction-length adjustment; no equivalent branch
// exists for other ISAs (e.g. x86), since this codebase targets Android's
// arm/arm64 ABIs for this fast frame-pointer unwinder.
// 中文：仅针对 arm64/arm：按固定指令长度做调整；其他指令集（例如 x86）
// 没有对应的分支，因为这个快速帧指针展开器只针对 Android 的 arm/arm64
// ABI。
#if defined(__aarch64__) || defined(__arm__)
  if (pc < kA64InstrLen) {
    return 0;
  }

#if defined(__aarch64__)
  if (pc > kA64InstrLen) {
    pc -= kA64InstrLen;
  }
#else
  if (pc & 1) {
    pc -= kT32InstrLen;
  } else {
    pc -= kA32InstrLen;
  }
#endif
#endif
  return pc;
}

/**
 * Captures a backtrace by walking the frame-pointer chain from the current
 * call frame up to (at most) kMaxBacktraceSize frames. This is the
 * unwinder LeakMonitor::RegisterAlloc calls on every hooked allocation
 * (hot path): it trades the completeness/robustness of a DWARF/.eh_frame-
 * based unwinder for the much lower per-call cost of simply chasing the
 * x29 frame-pointer chain, which is acceptable here since this only needs
 * to identify the allocating call site, not produce a fully verified crash
 * backtrace.
 *
 * 中文：从当前调用帧开始遍历帧指针链，最多捕获 kMaxBacktraceSize 帧，
 * 以此得到调用栈。这就是 LeakMonitor::RegisterAlloc 在每一次被 hook 的
 * 分配（热路径）上调用的展开器：它用简单地追踪 x29 帧指针链所带来的更低
 * 单次调用开销，换取放弃基于 DWARF/.eh_frame 展开器的完整性/健壮性；这里
 * 可以接受这种取舍，因为只需要定位到分配发生的调用点，而不需要生成一份
 * 完全经过验证的崩溃调用栈。
 */
KWAI_EXPORT size_t StackTrace::FastUnwind(uintptr_t *buf, size_t num_entries) {
  // Lazily computes this thread's stack bounds exactly once.
  // 中文：惰性地计算该线程的栈边界，且只计算一次。
  pthread_once(&once_control_tls, fast_unwind_init);
  auto begin = reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
  auto end = get_thread_stack_top();
  stack_t ss;
  // If unwinding is happening on an alternate signal stack, the thread's
  // normal stack bounds don't apply — use the sigaltstack's bounds instead
  // so the walk isn't wrongly terminated (or allowed to run wild).
  // 中文：如果展开动作正发生在一个备用信号栈上，该线程正常的栈边界就不
  // 适用了——此时改用 sigaltstack 的边界，以避免遍历被错误地提前终止
  // （或者反过来失控地跑飞）。
  if (sigaltstack(nullptr, &ss) == 0 && (ss.ss_flags & SS_ONSTACK)) {
    end = reinterpret_cast<uintptr_t>(ss.ss_sp) + ss.ss_size;
  }
  size_t num_frames = 0;
  while (num_frames < kMaxBacktraceSize) {
    auto *frame = reinterpret_cast<frame_record *>(begin);
    if (num_frames < num_entries) {
      buf[num_frames] = GetAdjustPC(frame->return_addr);
    }
    ++num_frames;
    // Sanity-check the next frame pointer before following it: it must move
    // forward past this frame_record, stay within this thread's stack
    // bounds, and be pointer-aligned — guards against a corrupted or
    // frame-pointer-omitted chain sending this off into unrelated memory.
    // 中文：在跟随下一个帧指针之前先做合理性检查：它必须向前越过当前这个
    // frame_record，必须落在本线程的栈边界之内，并且必须按指针对齐——用来
    // 防止一条损坏的、或省略了帧指针的链把遍历带到无关内存中去。
    if (frame->next_frame < begin + sizeof(frame_record) ||
        frame->next_frame >= end || frame->next_frame % sizeof(void *) != 0) {
      break;
    }
    begin = frame->next_frame;
  }
  return num_frames;
}