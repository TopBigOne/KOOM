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

// This file is the "hook" + "record" stage of the hook->record->scan->match
// pipeline: it interposes the malloc-family functions (via xhook rewriting
// the PLT/GOT, see utils/hook_helper.cpp) so every allocation/free made by
// the target .so's is observed here first, and defines the LeakMonitor
// singleton that stores per-allocation bookkeeping (address, size, call
// stack, thread name) used later by MemoryAnalyzer's reachability scan and
// the leak-matching logic in GetLeakAllocs().
// 中文：本文件实现 hook->record->scan->match 流程中的“hook（挂钩）”与
// “record（记录）”两个阶段：通过 xhook 重写 PLT/GOT（见
// utils/hook_helper.cpp）拦截 malloc 系列函数，使目标 .so 的每一次内存
// 分配/释放都先被这里观察到；同时定义了 LeakMonitor 单例，用于保存每次分配
// 的记录信息（地址、大小、调用栈、线程名），供后续 MemoryAnalyzer 的可达性
// 扫描以及 GetLeakAllocs() 中的泄漏匹配逻辑使用。
#define LOG_TAG "leak_monitor"
#include "leak_monitor.h"

#include <asm/mman.h>
#include <assert.h>
#include <dlfcn.h>
#include <kwai_util/kwai_macros.h>
#include <log/kcheck.h>
#include <log/log.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <unwind.h>
#include <utils/hook_helper.h>
#include <utils/stack_trace.h>

#include <functional>
#include <regex>
#include <thread>

#include "kwai_linker/kwai_dlfcn.h"
#include "utils/auto_time.h"

namespace kwai {
namespace leak_monitor {

// Zero-fills a freshly returned allocation. malloc/memalign/posix_memalign do
// not guarantee zeroed memory, so this avoids handing callers (and, more
// importantly, the later conservative scan) stale bytes from a previous
// allocation that could be misread as pointer-like garbage.
// 中文：将新返回的内存块清零。malloc/memalign/posix_memalign 并不保证内存
// 已清零，这样做可以避免调用方（更重要的是后续的保守式扫描）读到上一次分配
// 遗留下来的脏数据，从而被误判为“看起来像指针”的垃圾值。
#define CLEAR_MEMORY(ptr, size) \
  do {                          \
    if (ptr) {                  \
      memset(ptr, 0, size);     \
    }                           \
  } while (0)

// Renames e.g. malloc -> mallocMonitor so the wrapper symbol never collides
// with the real libc symbol it calls into.
// 中文：例如把 malloc 重命名为 mallocMonitor，避免包装函数的符号名与其内部
// 调用的真正 libc 符号发生冲突。
#define WRAP(x) x##Monitor
// Declares a hook wrapper function with the WRAP-generated name; xhook
// rewrites the GOT of target .so's so calls to `function` land here instead,
// letting us observe every allocation/free before/after delegating to the
// real implementation.
// 中文：以 WRAP 生成的名字声明一个 hook 包装函数；xhook 会重写目标 .so 的
// GOT，使得对 `function` 的调用改为落到这里，从而让我们能在转发给真正实现
// 之前/之后观察到每一次分配/释放。
#define HOOK(ret_type, function, ...) \
  static ALWAYS_INLINE ret_type WRAP(function)(__VA_ARGS__)

// Define allocator proxies; aligned_alloc included in API 28 and valloc/pvalloc
// can ignore in LP64 So we can't proxy aligned_alloc/valloc/pvalloc.
/**
 * Hooked replacement for free(). Called instead of the real free() because
 * xhook rewrote the caller's GOT entry to point here. Performs the real
 * free() first, then removes the corresponding record from
 * live_alloc_records_ so it stops being tracked as a live/leak candidate.
 *
 * 中文：free() 的 hook 替身。由于 xhook 已经把调用方的 GOT 表项重写指向
 * 这里，所以本函数会被调用来代替真正的 free()。它先执行真正的 free()，
 * 然后从 live_alloc_records_ 中移除对应的记录，使其不再被当作存活/泄漏
 * 候选进行跟踪。
 */
HOOK(void, free, void *ptr) {
  free(ptr);
  if (ptr) {
    LeakMonitor::GetInstance().UnregisterAlloc(
        reinterpret_cast<uintptr_t>(ptr));
  }
}

/**
 * Hooked replacement for malloc(). Performs the real allocation, then (if
 * above the size threshold) records address/size/backtrace/thread via
 * OnMonitor so the block can later be checked for reachability.
 *
 * 中文：malloc() 的 hook 替身。先执行真正的内存分配，然后（如果大小超过
 * 阈值）通过 OnMonitor 记录地址/大小/调用栈/线程信息，以便后续对该内存块
 * 进行可达性检查。
 */
HOOK(void *, malloc, size_t size) {
  auto result = malloc(size);
  LeakMonitor::GetInstance().OnMonitor(reinterpret_cast<intptr_t>(result),
                                       size);
  CLEAR_MEMORY(result, size);
  return result;
}

/**
 * Hooked replacement for realloc(). Unregisters the old address (its bytes
 * may move or be reused) before registering the new address/size, since
 * realloc is logically a free+alloc from the leak tracker's point of view.
 *
 * 中文：realloc() 的 hook 替身。在登记新地址/大小之前，先注销旧地址的记录
 * （因为原有内存可能被搬移或重新使用）；从泄漏跟踪器的角度看，realloc 在
 * 逻辑上等价于一次 free 加一次 alloc。
 */
HOOK(void *, realloc, void *ptr, size_t size) {
  auto result = realloc(ptr, size);
  if (ptr != nullptr) {
    LeakMonitor::GetInstance().UnregisterAlloc(
        reinterpret_cast<uintptr_t>(ptr));
  }
  LeakMonitor::GetInstance().OnMonitor(reinterpret_cast<intptr_t>(result),
                                       size);
  return result;
}

/**
 * Hooked replacement for calloc(). Records the allocation using the total
 * byte count (item_count * item_size) rather than either factor alone.
 *
 * 中文：calloc() 的 hook 替身。记录时使用总字节数（item_count * item_size），
 * 而不是单独使用其中某一个因子。
 */
HOOK(void *, calloc, size_t item_count, size_t item_size) {
  auto result = calloc(item_count, item_size);
  LeakMonitor::GetInstance().OnMonitor(reinterpret_cast<intptr_t>(result),
                                       item_count * item_size);
  return result;
}

/**
 * Hooked replacement for memalign(). Same bookkeeping as malloc, plus
 * zero-filling since memalign also gives no zero-init guarantee.
 *
 * 中文：memalign() 的 hook 替身。记录方式与 malloc 相同，同时需要清零，
 * 因为 memalign 同样不保证内存已初始化为零。
 */
HOOK(void *, memalign, size_t alignment, size_t byte_count) {
  auto result = memalign(alignment, byte_count);
  LeakMonitor::GetInstance().OnMonitor(reinterpret_cast<intptr_t>(result),
                                       byte_count);
  CLEAR_MEMORY(result, byte_count);
  return result;
}

/**
 * Hooked replacement for posix_memalign(). The allocated address is written
 * through the out-parameter *memptr (return value is only a status code),
 * so registration/zeroing operate on *memptr rather than on `result`.
 *
 * 中文：posix_memalign() 的 hook 替身。分配得到的地址是通过输出参数
 * *memptr 写回的（返回值只是一个状态码），因此记录/清零操作都作用于
 * *memptr，而不是 `result`。
 */
HOOK(int, posix_memalign, void **memptr, size_t alignment, size_t size) {
  auto result = posix_memalign(memptr, alignment, size);
  LeakMonitor::GetInstance().OnMonitor(reinterpret_cast<intptr_t>(*memptr),
                                       size);
  CLEAR_MEMORY(*memptr, size);
  return result;
}

/**
 * Returns the process-wide LeakMonitor singleton. All hook wrappers and the
 * JNI bridge (jni_leak_monitor.cpp) go through this single instance so there
 * is one shared live-allocation table and one MemoryAnalyzer.
 *
 * 中文：返回进程级唯一的 LeakMonitor 单例。所有 hook 包装函数以及 JNI 桥接
 * 层（jni_leak_monitor.cpp）都通过这个唯一实例访问，从而保证全进程共用同一份
 * 存活分配表和同一个 MemoryAnalyzer。
 */
LeakMonitor &LeakMonitor::GetInstance() {
  static LeakMonitor leak_monitor;
  return leak_monitor;
}

/**
 * Sets up the "hook" stage of the pipeline: builds a MemoryAnalyzer (which
 * dlopen's libmemunreachable.so up front so failure is detected before we
 * commit to hooking anything), then asks HookHelper to PLT-hook the
 * malloc-family symbols in the selected/ignored .so's. Idempotent — refuses
 * to install twice.
 *
 * 中文：搭建流水线的“hook”阶段：先构造 MemoryAnalyzer（它会预先 dlopen
 * libmemunreachable.so，这样在真正提交 hook 动作之前就能发现失败），然后
 * 请求 HookHelper 对选中/忽略列表中的 .so 进行 malloc 系列符号的 PLT hook。
 * 该函数是幂等的——拒绝重复安装。
 */
bool LeakMonitor::Install(std::vector<std::string> *selected_list,
                          std::vector<std::string> *ignore_list) {
  KCHECK(!has_install_monitor_);

  // Reinstall can't hook again
  if (has_install_monitor_) {
    return true;
  }

  memory_analyzer_ = std::make_unique<MemoryAnalyzer>();
  if (!memory_analyzer_->IsValid()) {
    ALOGE("memory_analyzer_ NOT Valid");
    return false;
  }

  // Default: only hook .so's installed under /data (the app's own/bundled
  // libraries), never system libs under /system, to keep overhead and risk
  // bounded.
  // 中文：默认只 hook 安装在 /data 下的 .so（即 App 自身/内置的库），
  // 绝不 hook /system 下的系统库，以控制开销与风险范围。
  std::vector<const std::string> register_pattern = {"^/data/.*\\.so$"};
  // Never hook this monitor's own .so or the xhook engine's own .so, or the
  // hook wrappers would recursively call themselves when this library itself
  // allocates memory.
  // 中文：绝不能 hook 本监控库自身的 .so 或 xhook 引擎自身的 .so，否则当
  // 本库自身发生内存分配时，hook 包装函数会递归调用自身。
  std::vector<const std::string> ignore_pattern = {".*/libkoom-native.so$",
                                                   ".*/libxhook_lib.so$"};

  if (ignore_list != nullptr) {
    for (std::string &item : *ignore_list) {
      ignore_pattern.push_back(".*/" + item + ".so$");
    }
  }
  if (selected_list != nullptr && !selected_list->empty()) {
    // only hook the so in selected list
    register_pattern.clear();
    for (std::string &item : *selected_list) {
      register_pattern.push_back("^/data/.*/" + item + ".so$");
    }
  }
  std::vector<std::pair<const std::string, void *const>> hook_entries = {
      std::make_pair("malloc", reinterpret_cast<void *>(WRAP(malloc))),
      std::make_pair("realloc", reinterpret_cast<void *>(WRAP(realloc))),
      std::make_pair("calloc", reinterpret_cast<void *>(WRAP(calloc))),
      std::make_pair("memalign", reinterpret_cast<void *>(WRAP(memalign))),
      std::make_pair("posix_memalign",
                     reinterpret_cast<void *>(WRAP(posix_memalign))),
      std::make_pair("free", reinterpret_cast<void *>(WRAP(free)))};

  if (HookHelper::HookMethods(register_pattern, ignore_pattern, hook_entries)) {
    has_install_monitor_ = true;
    return true;
  }

  HookHelper::UnHookMethods();
  live_alloc_records_.Clear();
  memory_analyzer_.reset(nullptr);
  ALOGE("%s Fail", __FUNCTION__);
  return false;
}

/**
 * Reverses Install(): removes the PLT hooks (subsequent malloc/free calls go
 * straight to the real libc again), drops all recorded live allocations, and
 * releases the MemoryAnalyzer (which dlclose's libmemunreachable.so).
 *
 * 中文：撤销 Install() 的效果：移除 PLT hook（此后 malloc/free 调用会重新
 * 直接落到真正的 libc 实现），清空所有已记录的存活分配，并释放
 * MemoryAnalyzer（其内部会 dlclose libmemunreachable.so）。
 */
void LeakMonitor::Uninstall() {
  KCHECKV(has_install_monitor_)
  has_install_monitor_ = false;
  HookHelper::UnHookMethods();
  live_alloc_records_.Clear();
  memory_analyzer_.reset(nullptr);
}

/**
 * Sets the minimum allocation size (bytes) that will be recorded. Smaller
 * allocations are ignored by OnMonitor to bound the per-call overhead and
 * memory cost of the hot allocation hooks.
 *
 * 中文：设置将被记录的最小分配字节数。小于该阈值的分配会被 OnMonitor
 * 忽略，以控制这些高频调用的 hook 函数在每次调用上的开销及内存成本。
 */
void LeakMonitor::SetMonitorThreshold(size_t threshold) {
  KCHECK(has_install_monitor_);
  alloc_threshold_ = threshold;
}

/**
 * The "match" stage of the pipeline: triggers MemoryAnalyzer's mark-and-sweep
 * reachability scan, then intersects its "unreachable" address ranges with
 * this process's still-live allocation records to find blocks that are both
 * (a) still tracked as allocated-and-not-freed and (b) unreachable from any
 * root per the conservative scan — i.e. leaked native memory. Matched
 * records are also evicted from live_alloc_records_ since they will never be
 * legitimately freed.
 *
 * 中文：流水线的“match（匹配）”阶段：先触发 MemoryAnalyzer 的标记-清除
 * 可达性扫描，再将其得到的“不可达”地址范围与本进程当前仍然存活的分配记录
 * 做交集，找出同时满足以下两个条件的内存块：(a) 仍被记录为“已分配且未释放”；
 * (b) 根据保守式扫描判断从任何根都不可达——即发生了 native 内存泄漏。
 * 匹配到的记录也会从 live_alloc_records_ 中被移除，因为它们不可能再被
 * 正常地释放了。
 */
std::vector<std::shared_ptr<AllocRecord>> LeakMonitor::GetLeakAllocs() {
  KCHECK(has_install_monitor_);
  auto unreachable_allocs = memory_analyzer_->CollectUnreachableMem();
  std::vector<std::shared_ptr<AllocRecord>> live_allocs;
  std::vector<std::shared_ptr<AllocRecord>> leak_allocs;

  // Collect live memory blocks
  auto collect_func = [&](std::shared_ptr<AllocRecord> &alloc_info) -> void {
    live_allocs.push_back(alloc_info);
  };
  live_alloc_records_.Dump(collect_func);

  // Ranges compared here, not raw pointer equality: libmemunreachable reports
  // "unreachable at <addr>, <size> bytes" for whatever block boundaries its
  // own allocator bookkeeping sees, which should coincide with our recorded
  // [address, address+size) range for a genuine leak of that same block.
  // 中文：这里比较的是地址区间，而不是原始指针相等：libmemunreachable
  // 报告的是“在 <addr> 处有 <size> 字节不可达”，其块边界来自它自身分配器的
  // 记录信息；对于同一个内存块真正发生泄漏的情况，这个区间应当与我们记录的
  // [address, address+size) 区间重合。
  auto is_leak = [&](decltype(unreachable_allocs)::value_type &unreachable,
                     std::shared_ptr<AllocRecord> &live) -> bool {
    // live->address was stored obfuscated (CONFUSE == bitwise NOT); revert it
    // to compare against the real address libmemunreachable reported.
    // 中文：live->address 存储时是经过混淆的（CONFUSE 即按位取反），这里
    // 需要还原成真实地址，才能与 libmemunreachable 报告的真实地址比较。
    auto live_start = CONFUSE(live->address);
    auto live_end = live_start + live->size;
    auto unreachable_start = unreachable.first;
    auto unreachable_end = unreachable_start + unreachable.second;
    // TODO why
    return live_start == unreachable_start ||
           live_start >= unreachable_start && live_end <= unreachable_end;
  };
  // Check leak allocation (unreachable && not free)
  for (auto &live : live_allocs) {
    for (auto &unreachable : unreachable_allocs) {
      if (is_leak(unreachable, live)) {
        leak_allocs.push_back(live);
        // Just remove leak allocation(never be free)
        // live->address has been confused, we need to revert it first
        UnregisterAlloc(CONFUSE(live->address));
      }
    }
  }

  return leak_allocs;
}

/**
 * Returns a monotonically increasing counter of allocations recorded so far.
 * Exposed to Java (see jni_leak_monitor.cpp) so callers can snapshot "how far
 * along" allocation tracking is, e.g. to only report leaks allocated after a
 * given point.
 *
 * 中文：返回目前为止已记录分配次数的单调递增计数器。该接口会暴露给 Java
 * 层（见 jni_leak_monitor.cpp），使调用方可以记录“分配跟踪目前进行到哪里”
 * 的快照，例如只上报某个时间点之后分配的泄漏。
 */
uint64_t LeakMonitor::CurrentAllocIndex() {
  KCHECK(has_install_monitor_);
  return alloc_index_.load(std::memory_order_relaxed);
}

/**
 * The core of the "record" stage: called from every hooked allocator on the
 * hot allocation path. Captures the calling thread's name, a fast frame-
 * pointer backtrace, size and a monotonic index into an AllocRecord, and
 * inserts it into the live-allocation table keyed by (obfuscated) address.
 * Cost here directly adds to every malloc/calloc/memalign/posix_memalign
 * call in the hooked .so's, so work is kept minimal.
 *
 * 中文：这是“record（记录）”阶段的核心：在每一次被 hook 的分配调用的热路径
 * 上都会被调用。它把调用线程名、一份基于帧指针的快速调用栈、大小以及一个
 * 单调递增的序号，一并写入一个 AllocRecord，并以（混淆后的）地址为键插入
 * 存活分配表。这里的开销会直接叠加到每一次被 hook 的 .so 中的
 * malloc/calloc/memalign/posix_memalign 调用上，因此这里的工作量要尽量小。
 */
ALWAYS_INLINE void LeakMonitor::RegisterAlloc(uintptr_t address, size_t size) {
  if (!address || !size) {
    return;
  }

  // Frame-pointer unwinding (see utils/stack_trace.cpp) is used instead of
  // DWARF/.eh_frame unwinding because it is cheap enough to run on every
  // allocation; this runs on the hot allocation path so unwind speed matters
  // more than completeness/robustness here.
  // 中文：这里使用基于帧指针的回溯（见 utils/stack_trace.cpp），而不是
  // DWARF/.eh_frame 回溯，因为前者足够廉价，可以在每次分配时都执行；由于
  // 这里处于分配的热路径上，回溯速度比结果的完整性/健壮性更重要。
  auto unwind_backtrace = [](uintptr_t *frames, uint32_t *frame_count) {
    *frame_count = StackTrace::FastUnwind(frames, kMaxBacktraceSize);
  };

  // thread_local: PR_GET_NAME is only read once per thread (in ThreadInfo's
  // constructor) and cached here, instead of doing a prctl() syscall on
  // every single allocation.
  // 中文：thread_local：PR_GET_NAME 只在每个线程第一次用到时读取一次
  // （在 ThreadInfo 的构造函数中）并缓存在这里，而不是在每一次分配时都执行
  // 一次 prctl() 系统调用。
  thread_local ThreadInfo thread_info;
  auto alloc_record = std::make_shared<AllocRecord>();
  // CONFUSE (bitwise NOT, see leak_monitor.h) is a cheap obfuscation of the
  // raw address so a stray dump of the record's memory doesn't trivially
  // reveal live heap addresses.
  // 中文：CONFUSE（按位取反，见 leak_monitor.h）是对原始地址的一种廉价混淆
  // 处理，这样即便记录所在的内存被意外 dump 出来，也不会直接暴露存活的堆
  // 地址。
  alloc_record->address = CONFUSE(address);
  alloc_record->size = size;
  alloc_record->index = alloc_index_++;
  memcpy(alloc_record->thread_name, thread_info.name, kMaxThreadNameLen);
  unwind_backtrace(alloc_record->backtrace, &(alloc_record->num_backtraces));
  // Keyed by the same obfuscated address so lookups/erasures (UnregisterAlloc)
  // stay consistent with how the address was stored.
  // 中文：使用同样经过混淆的地址作为键，以保证后续查找/删除
  // （UnregisterAlloc）时与存储时保持一致。
  live_alloc_records_.Put(CONFUSE(address), std::move(alloc_record));
}

/**
 * Removes the bookkeeping record for an address that has just been freed (or
 * reallocated away from). Called from the free/realloc hooks; the address is
 * re-obfuscated with CONFUSE to match the key used in RegisterAlloc.
 *
 * 中文：移除某个刚被释放（或在 realloc 中被替换掉）的地址所对应的记录。
 * 由 free/realloc 的 hook 函数调用；这里会用 CONFUSE 对地址重新做同样的
 * 混淆处理，以匹配 RegisterAlloc 中使用的键。
 */
ALWAYS_INLINE void LeakMonitor::UnregisterAlloc(uintptr_t address) {
  live_alloc_records_.Erase(CONFUSE(address));
}

/**
 * Entry point called by every hooked allocator after the real allocation
 * succeeds. Cheaply filters out disabled-monitor and below-threshold/null
 * allocations before paying the cost of RegisterAlloc's backtrace capture.
 *
 * 中文：每一个被 hook 的分配函数在真正分配成功之后都会调用这里的入口函数。
 * 它会先以很小的代价过滤掉“监控未启用”以及“大小低于阈值/空指针”的分配，
 * 然后才真正付出 RegisterAlloc 中捕获调用栈的开销。
 */
ALWAYS_INLINE void LeakMonitor::OnMonitor(uintptr_t address, size_t size) {
  if (!has_install_monitor_ || !address ||
      size < alloc_threshold_.load(std::memory_order_relaxed)) {
    return;
  }

  RegisterAlloc(address, size);
}
}  // namespace leak_monitor
}  // namespace kwai