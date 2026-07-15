/*
 * Copyright (C) 2012 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef KOOM_KOOM_NATIVE_SRC_MAIN_JNI_INCLUDE_MEMORY_MAP_H_
#define KOOM_KOOM_NATIVE_SRC_MAIN_JNI_INCLUDE_MEMORY_MAP_H_

#include <sys/cdefs.h>

#include <mutex>
#include <set>
#include <string>

#define LIB_ART "libart.so"
#define OAT_SUFFEX ".oat"
#define ODEX_SUFFEX ".odex"
#define DEX_SUFFEX ".dex"

// One parsed row of /proc/self/maps: an address range plus what (if
// anything) is mapped there, used both to bound raw memory reads safely and
// to symbolize backtrace PCs into "which .so + what offset".
// 中文：/proc/self/maps 中解析出的一行：一个地址范围，加上该范围内映射了
// 什么（如果有的话），既用来安全地限定原始内存读取的边界，也用来把调用栈
// PC 符号化为“属于哪个 .so 的哪个偏移”。
struct MapEntry {
  MapEntry(uintptr_t start, uintptr_t end, uintptr_t offset, const char *name,
           size_t name_len, int flags)
      : start(start),
        end(end),
        offset(offset),
        name(name, name_len),
        flags(flags) {}

  // Constructs a zero-size "probe" entry used only as a search key when
  // looking up which real MapEntry a given PC falls into (see
  // MapEntryCompare below).
  // 中文：构造一个零大小的“探测”条目，仅用作查找某个 PC 落在哪个真实
  // MapEntry 中时的搜索键（见下面的 MapEntryCompare）。
  explicit MapEntry(uintptr_t pc) : start(pc), end(pc) {}

  // Whether this mapped library is part of the Android runtime itself
  // (libart.so or compiled .oat/.odex/.dex images) rather than app/native
  // code, so its frames can be dropped from a reported leak stack trace.
  // 中文：判断这个已映射的库是否属于 Android 运行时本身（libart.so 或
  // 编译产物 .oat/.odex/.dex 镜像），而不是 App/native 代码，这样其对应的
  // 帧就可以从上报的泄漏调用栈中被丢弃。
  bool NeedIgnore() {
    auto ends_with = [](std::string &target,
                        const std::string &suffix) -> bool {
      return target.size() >= suffix.size() &&
             target.substr(target.size() - suffix.size(), suffix.size()) ==
                 suffix;
    };
    return ends_with(name, LIB_ART) || ends_with(name, OAT_SUFFEX) ||
           ends_with(name, ODEX_SUFFEX) || ends_with(name, DEX_SUFFEX);
  }

  uintptr_t start;
  uintptr_t end;
  uintptr_t offset;
  uintptr_t load_bias;
  uintptr_t elf_start_offset = 0;
  std::string name;
  int flags;
  bool init = false;
  bool valid = false;
};

// Ordering comparator that returns equivalence for overlapping entries
// Lets a zero-size probe MapEntry(pc) be used as a std::set search key: two
// entries compare "equal" (neither less than the other) whenever their
// ranges overlap, so searching for a bare pc finds the real range entry that
// contains it.
// 中文：使一个零大小的探测 MapEntry(pc) 可以被用作 std::set 的搜索键：
// 只要两个条目的地址范围有重叠，就会被比较为“相等”（谁都不小于对方），
// 因此用一个裸的 pc 去查找时，能够找到真正包含它的那个范围条目。
struct MapEntryCompare {
  bool operator()(const MapEntry *a, const MapEntry *b) const {
    return a->end <= b->start;
  }
};

/**
 * Enumerates this process's own virtual address space by parsing
 * /proc/self/maps in user space (no special privilege needed), and uses that
 * to symbolize raw backtrace PCs captured during the "record" stage into
 * which .so (and offset within it) they belong to.
 *
 * 中文：通过在用户态解析 /proc/self/maps（无需任何特殊权限）来枚举本进程
 * 自身的虚拟地址空间，并据此把“record”阶段捕获到的原始调用栈 PC 符号化，
 * 判断它们属于哪个 .so（以及在该库内的偏移）。
 */
class MemoryMap {
 public:
  MemoryMap() = default;
  ~MemoryMap();

  /** Finds which mapped library `pc` falls in and its offset within it.
   *
   * 中文：找出 `pc` 落在哪个已映射的库中，以及它在该库内的偏移量。
   */
  MapEntry *CalculateRelPc(uintptr_t pc, uintptr_t *rel_pc = nullptr);
  /** Formats a human-readable "so(+offset) symbol+delta" line for `pc`.
   *
   * 中文：为 `pc` 格式化出一行可读文本："so(+偏移) 符号+增量"。
   */
  std::string FormatSymbol(MapEntry *entry, uintptr_t pc);

 private:
  /** Reads and parses /proc/self/maps into entries_.
   *
   * 中文：读取并解析 /proc/self/maps，填充进 entries_。
   */
  bool ReadMaps();

  std::set<MapEntry *, MapEntryCompare> entries_;
};

#endif  // KOOM_KOOM_NATIVE_SRC_MAIN_JNI_INCLUDE_MEMORY_MAP_H_
