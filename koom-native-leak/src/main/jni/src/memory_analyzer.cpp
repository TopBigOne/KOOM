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

// This file is the "scan" stage of the hook->record->scan->match pipeline:
// it drives Android's system libmemunreachable.so to perform a conservative
// mark-and-sweep reachability scan of this process's own memory (the same
// technique used by tracing garbage collectors, applied here to untyped
// native memory), and returns the address ranges it judged unreachable.
// LeakMonitor::GetLeakAllocs() then intersects these ranges with the still-
// live allocations recorded by leak_monitor.cpp to find actual leaks.
// 中文：本文件实现 hook->record->scan->match 流程中的“scan（扫描）”阶段：
// 通过驱动 Android 系统库 libmemunreachable.so，对本进程自身的内存做一次
// 保守式的标记-清除可达性扫描（与追踪式垃圾回收器所用的技术相同，只不过
// 这里应用于没有类型信息的 native 内存），并返回其判定为不可达的地址区间。
// 之后 LeakMonitor::GetLeakAllocs() 会把这些区间与 leak_monitor.cpp 中记录
// 的仍然存活的分配做交集，从而找出真正的内存泄漏。
#define LOG_TAG "memory_analyzer"
#include "memory_analyzer.h"

#include <dlfcn.h>
#include <log/log.h>
#include <sys/prctl.h>

#include <regex>

#include "kwai_linker/kwai_dlfcn.h"

namespace kwai {
namespace leak_monitor {
static const char *kLibMemUnreachableName = "libmemunreachable.so";
// Just need the symbol in arm64-v8a so
// API level > Android O
// Itanium C++ mangled name of android::GetUnreachableMemoryString(bool, size_t)
// as exported by libmemunreachable.so on API levels above Oreo.
// 中文：这是 android::GetUnreachableMemoryString(bool, size_t) 按 Itanium
// C++ ABI 修饰后的符号名，是高于 Oreo 的 API 级别中 libmemunreachable.so
// 导出的符号名。
static const char *kGetUnreachableMemoryStringSymbolAboveO =
    "_ZN7android26GetUnreachableMemoryStringEbm";
// API level <= Android O
// Same function, but mangled/exported as a free (non-namespaced) C++ symbol
// on Android O and below — the AOSP implementation changed its symbol
// signature across API levels, so both spellings must be tried.
// 中文：同一个函数，但在 Android O 及以下版本中被修饰/导出为一个非命名
// 空间下的自由函数符号——因为 AOSP 的实现在不同 API 级别之间改变了符号
// 签名，所以两种写法都需要尝试。
static const char *kGetUnreachableMemoryStringSymbolBelowO =
    "_Z26GetUnreachableMemoryStringbm";

/**
 * Prepares the "scan" stage by dynamically loading Android's system
 * libmemunreachable.so and resolving its GetUnreachableMemoryString symbol.
 * This is not linked at build time (it is a private platform library, and
 * its mangled symbol name varies by API level), so dlopen/dlsym are used to
 * bind it at runtime instead; if either step fails, IsValid() will report
 * this analyzer (and therefore the whole leak monitor) as unusable.
 *
 * 中文：通过动态加载 Android 系统库 libmemunreachable.so 并解析其
 * GetUnreachableMemoryString 符号，为“scan”阶段做准备。该库并未在构建期
 * 链接（它是平台私有库，其修饰后的符号名还会随 API 级别变化），因此改用
 * dlopen/dlsym 在运行期完成绑定；只要其中一步失败，IsValid() 就会报告本
 * 分析器（进而整个 leak monitor）不可用。
 */
MemoryAnalyzer::MemoryAnalyzer()
    : get_unreachable_fn_(nullptr), handle_(nullptr) {
  // dlopen the system reachability-analysis library rather than linking
  // against it directly, since it's an internal AOSP library not part of the
  // NDK ABI and not guaranteed to be linkable at build time.
  // 中文：这里对系统的可达性分析库使用 dlopen，而不是直接链接，因为它是
  // AOSP 内部库，不属于 NDK ABI 的一部分，也不保证在构建期一定可链接。
  auto handle = kwai::linker::DlFcn::dlopen(kLibMemUnreachableName, RTLD_NOW);
  if (!handle) {
    ALOGE("dlopen %s error: %s", kLibMemUnreachableName, dlerror());
    return;
  }

  // Resolve the correct mangled symbol name for the running device's API
  // level, since the exported symbol's mangling differs across Android
  // versions (see comments on the two symbol name constants above).
  // 中文：根据当前设备的 API 级别解析正确的修饰符号名，因为导出符号的
  // 修饰方式在不同 Android 版本间是不同的（参见上面两个符号名常量的注释）。
  if (android_get_device_api_level() > __ANDROID_API_O__) {
    get_unreachable_fn_ =
        reinterpret_cast<GetUnreachableFn>(kwai::linker::DlFcn::dlsym(
            handle, kGetUnreachableMemoryStringSymbolAboveO));
  } else {
    get_unreachable_fn_ =
        reinterpret_cast<GetUnreachableFn>(kwai::linker::DlFcn::dlsym(
            handle, kGetUnreachableMemoryStringSymbolBelowO));
  }
}

/** Releases the dlopen'd libmemunreachable.so handle, if one was obtained.
 *
 * 中文：释放 dlopen 得到的 libmemunreachable.so 句柄（如果曾经成功获取过）。
 */
MemoryAnalyzer::~MemoryAnalyzer() {
  if (handle_) {
    kwai::linker::DlFcn::dlclose(handle_);
  }
}

/**
 * Reports whether the libmemunreachable symbol was successfully resolved;
 * callers must check this before invoking CollectUnreachableMem().
 *
 * 中文：报告 libmemunreachable 的符号是否解析成功；调用方在调用
 * CollectUnreachableMem() 之前必须先检查这个状态。
 */
bool MemoryAnalyzer::IsValid() { return get_unreachable_fn_ != nullptr; }

/**
 * Runs the actual "scan" stage: invokes libmemunreachable's conservative
 * mark-and-sweep reachability analysis over this process's own memory
 * (walking registers/stacks/globals as roots, scanning for values that look
 * like heap pointers — the same idea a tracing GC uses, but here there is no
 * type metadata, so any in-range value is conservatively treated as a
 * possible pointer) and parses its textual report into a list of
 * (address, size) ranges that were found unreachable.
 *
 * 中文：真正执行“scan”阶段：调用 libmemunreachable 对本进程自身内存做
 * 保守式的标记-清除可达性分析（以寄存器/栈/全局变量等作为根进行遍历，
 * 扫描那些“看起来像堆指针”的数值——思路与追踪式垃圾回收器相同，只不过这里
 * 没有类型元数据，所以任何落在有效范围内的数值都会被保守地当作可能的指针
 * 处理），并把其文本形式的报告解析成一组被判定为不可达的
 * (地址, 大小) 区间列表。
 */
std::vector<std::pair<uintptr_t, size_t>>
MemoryAnalyzer::CollectUnreachableMem() {
  std::vector<std::pair<uintptr_t, size_t>> unreachable_mem;

  if (!IsValid()) {
    ALOGE("MemoryAnalyzer NOT valid");
    return std::move(unreachable_mem);
  }

  // Remember the process's current "dumpable" flag so it can be restored
  // afterward instead of being permanently altered.
  // 中文：先记录进程当前的“dumpable（可转储）”标志，以便扫描结束后恢复，
  // 而不是永久性地改变它。
  int origin_dumpable = prctl(PR_GET_DUMPABLE);

  // libmemunreachable NOT work in release apk because it using ptrace
  // libmemunreachable needs ptrace-like access to this process's own memory,
  // registers and threads to walk roots and scan for pointer-like values;
  // Linux only allows that when the process is marked "dumpable" (normally
  // used to gate core-dump/ptrace access for security). Non-debuggable
  // release builds run non-dumpable by default, so it must be flipped on
  // here for the duration of the scan.
  // 中文：libmemunreachable 需要类似 ptrace 的权限来访问本进程自身的内存、
  // 寄存器和线程，以遍历根并扫描类似指针的数值；而 Linux 只有在进程被标记
  // 为“dumpable”时才允许这样做（该标志通常用来控制 core dump/ptrace 权限，
  // 是一项安全限制）。非 debuggable 的 release 构建默认是不可 dump 的，
  // 因此这里需要在扫描期间临时把它打开。
  if (prctl(PR_SET_DUMPABLE, 1) == -1) {
    ALOGE("Set process dumpable Fail");
    return std::move(unreachable_mem);
  }

  // Note: time consuming
  std::string unreachable_memory = get_unreachable_fn_(false, 1024);

  // Unset "dumpable" for security
  // Restore the original dumpable value immediately after the scan so this
  // process doesn't remain ptrace-able/dumpable for longer than necessary,
  // keeping the security boundary weakened only transiently.
  // 中文：扫描结束后立即恢复原始的 dumpable 值，避免进程长时间处于
  // 可被 ptrace/dump 的状态，使这项安全边界的削弱只是暂时性的。
  prctl(PR_SET_DUMPABLE, origin_dumpable);

  // libmemunreachable's API only returns a human-readable text report (not a
  // structured list), so its "N bytes unreachable at 0x..." lines have to be
  // regex-scraped back into (address, size) pairs.
  // 中文：libmemunreachable 的接口只返回一份人类可读的文本报告（而非结构化
  // 列表），因此需要用正则表达式把其中形如“N bytes unreachable at 0x...”
  // 的行重新解析成 (地址, 大小) 数据对。
  std::regex filter_regex("[0-9]+ bytes unreachable at [A-Za-z0-9]+");
  std::sregex_iterator unreachable_begin(
      unreachable_memory.begin(), unreachable_memory.end(), filter_regex);
  std::sregex_iterator unreachable_end;
  for (; unreachable_begin != unreachable_end; ++unreachable_begin) {
    const auto& line = unreachable_begin->str();
    auto address =
        std::stoul(line.substr(line.find_last_of(' ') + 1,
                               line.length() - line.find_last_of(' ') - 1),
                   0, 16);
    auto size = std::stoul(line.substr(0, line.find_first_of(' ')));
    unreachable_mem.emplace_back(address, size);
  }
  return std::move(unreachable_mem);
}
}  // namespace leak_monitor
}  // namespace kwai
