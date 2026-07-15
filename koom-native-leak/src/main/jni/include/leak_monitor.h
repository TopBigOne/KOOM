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

#ifndef KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_LEAK_MONITOR_H_
#define KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_LEAK_MONITOR_H_

#include <linux/prctl.h>
#include <sys/prctl.h>

#include <list>
#include <vector>

#include "constants.h"
#include "memory_analyzer.h"
#include "utils/concurrent_hash_map.h"

// Lightweight obfuscation (bitwise NOT) applied to raw heap addresses before
// they are stored in / looked up from live_alloc_records_, so that a stray
// memory dump of this process doesn't trivially expose live native heap
// addresses. It is its own inverse, so CONFUSE(CONFUSE(x)) == x.
// 中文：对原始堆地址做一次轻量级混淆（按位取反）后再存入/从
// live_alloc_records_ 中查找，这样即便进程内存被意外 dump 出来，也不会
// 直接暴露存活的 native 堆地址。该操作是自身的逆运算，即
// CONFUSE(CONFUSE(x)) == x。
#define CONFUSE(address) (~(address))

namespace kwai {
namespace leak_monitor {
// Bookkeeping captured by the "record" stage for one still-outstanding
// allocation: enough to later report it as a leak (size, allocating thread,
// call stack) if the "scan" stage finds it unreachable.
// 中文："record"阶段为一次仍未释放的分配所记录的信息：包含足够的数据
// （大小、分配线程、调用栈），以便在“scan”阶段判定其不可达后，能据此上报
// 为一次泄漏。
struct AllocRecord {
  uint64_t index;
  uint32_t size;
  intptr_t address;
  uint32_t num_backtraces;
  uintptr_t backtrace[kMaxBacktraceSize];
  char thread_name[kMaxThreadNameLen];
};

// Per-thread cached identity used to tag each AllocRecord with which thread
// performed the allocation.
// 中文：每个线程缓存的身份信息，用来标记某个 AllocRecord 是由哪个线程
// 执行的分配。
struct ThreadInfo {
  char name[kMaxThreadNameLen];
  ThreadInfo() {
    // PR_GET_NAME reads the calling thread's name (as set via
    // pthread_setname_np/prctl(PR_SET_NAME)) into `name`; this is looked up
    // once per thread (see the thread_local usage in RegisterAlloc) rather
    // than on every allocation, since prctl is a syscall.
    // 中文：PR_GET_NAME 会把调用线程的名字（通过
    // pthread_setname_np/prctl(PR_SET_NAME) 设置）读入 `name`；这个查询
    // 每个线程只做一次（见 RegisterAlloc 中 thread_local 的用法），而不是
    // 每次分配都做一次，因为 prctl 是一次系统调用。
    if (prctl(PR_GET_NAME, name)) {
      memcpy(name, "unknown", kMaxThreadNameLen);
    }
  }

  ~ThreadInfo() = default;
};

/**
 * Singleton coordinating the whole hook->record->scan->match pipeline for
 * native leak detection: installs/uninstalls the malloc-family hooks,
 * records live allocations, and (via MemoryAnalyzer) checks which recorded
 * allocations are unreachable to identify leaks.
 *
 * 中文：协调整个 hook->record->scan->match 流水线的单例，用于 native
 * 内存泄漏检测：安装/卸载 malloc 系列 hook，记录存活的分配，并（通过
 * MemoryAnalyzer）检查哪些已记录的分配已不可达，从而识别出泄漏。
 */
class LeakMonitor {
 public:
  /** Accesses the process-wide singleton instance.
   *
   * 中文：访问进程级唯一的单例实例。
   */
  static LeakMonitor &GetInstance();
  /** Installs the malloc-family PLT hooks and starts tracking allocations.
   *
   * 中文：安装 malloc 系列的 PLT hook，并开始跟踪内存分配。
   */
  bool Install(std::vector<std::string> *selected_list,
               std::vector<std::string> *ignore_list);
  /** Removes the hooks and clears all tracked allocation state.
   *
   * 中文：移除 hook，并清空所有已跟踪的分配状态。
   */
  void Uninstall();
  /** Sets the minimum allocation size (bytes) that will be tracked.
   *
   * 中文：设置将被跟踪的最小分配字节数。
   */
  void SetMonitorThreshold(size_t threshold);
  /** Runs the scan+match stages and returns confirmed leaked allocations.
   *
   * 中文：执行 scan+match 阶段，并返回已确认泄漏的分配列表。
   */
  std::vector<std::shared_ptr<AllocRecord>> GetLeakAllocs();
  /** Returns the current monotonic allocation counter.
   *
   * 中文：返回当前单调递增的分配计数器。
   */
  uint64_t CurrentAllocIndex();
  /** Hot-path entry point called by every hooked allocator.
   *
   * 中文：每个被 hook 的分配函数都会调用的热路径入口。
   */
  void OnMonitor(uintptr_t address, size_t size);
  /** Captures and stores bookkeeping for one new allocation.
   *
   * 中文：为一次新的分配捕获并存储记录信息。
   */
  void RegisterAlloc(uintptr_t address, size_t size);
  /** Removes bookkeeping for an address that was freed/reallocated away.
   *
   * 中文：移除某个已被释放/被 realloc 替换掉的地址所对应的记录。
   */
  void UnregisterAlloc(uintptr_t address);

 private:
  LeakMonitor()
      : alloc_index_(0),
        has_install_monitor_(false),
        live_alloc_records_(),
        alloc_threshold_(kDefaultAllocThreshold),
        memory_analyzer_() {}
  ~LeakMonitor() = default;
  LeakMonitor(const LeakMonitor &);
  LeakMonitor &operator=(const LeakMonitor &);
  std::unique_ptr<MemoryAnalyzer> memory_analyzer_;
  // Sharded/bucketed hash map (see utils/concurrent_hash_map.h): allocations
  // and frees happen concurrently on every thread in the process, so a
  // single global lock here would serialize all hooked malloc/free calls
  // process-wide.
  // 中文：分片/分桶的哈希表（见 utils/concurrent_hash_map.h）：分配与释放
  // 会在进程内的每个线程上并发发生，如果这里用单一的全局锁，会导致全进程
  // 所有被 hook 的 malloc/free 调用都被串行化。
  ConcurrentHashMap<intptr_t, std::shared_ptr<AllocRecord>> live_alloc_records_;
  std::atomic<uint64_t> alloc_index_;
  std::atomic<bool> has_install_monitor_;
  std::atomic<size_t> alloc_threshold_;
};
}  // namespace leak_monitor
}  // namespace kwai
#endif  // KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_LEAK_MONITOR_H_
