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

// Parses /proc/self/maps to enumerate this process's own virtual address
// space (loaded library ranges, permissions, ELF load bias) purely from user
// space, with no special privilege required. Used to symbolize captured
// backtrace PCs (which .so + offset a return address belongs to) for the
// leak reports built in jni_leak_monitor.cpp.
// 中文：解析 /proc/self/maps 来枚举本进程自身的虚拟地址空间（已加载库的
// 地址范围、权限、ELF 加载偏移），全程只在用户态完成，不需要任何特殊权限。
// 用来把捕获到的调用栈 PC 符号化（判断一个返回地址属于哪个 .so 的哪个
// 偏移），供 jni_leak_monitor.cpp 构建泄漏报告使用。
#define LOG_TAG "memory_map"
#include "memory_map.h"

#include <ctype.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <elf.h>
#include <inttypes.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <vector>

#if defined(__LP64__)
#define PAD_PTR "016" PRIxPTR
#else
#define PAD_PTR "08" PRIxPTR
#endif

// Format of /proc/<PID>/maps:
// 6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /system/lib/libcomposer.so
/**
 * Parses one line of /proc/self/maps text into a MapEntry (start/end
 * address, permission flags, file offset, mapped file name). This is how
 * mapped-library ranges are discovered without needing any special
 * privilege — /proc/self/maps is readable by the process about itself.
 *
 * 中文：把 /proc/self/maps 文本中的一行解析成一个 MapEntry（起止地址、
 * 权限标志、文件偏移、映射的文件名）。这就是无需任何特殊权限即可发现已
 * 映射库地址范围的方式——/proc/self/maps 对进程自身是可读的。
 */
static MapEntry *ParseLine(char *line) {
  uintptr_t start;
  uintptr_t end;
  uintptr_t offset;
  int flags;
  char permissions[5];
  int name_pos;
  if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %*x:%*x %*d %n",
             &start, &end, permissions, &offset, &name_pos) < 2) {
    return nullptr;
  }

  const char *name = line + name_pos;
  size_t name_len = strlen(name);
  if (name_len && name[name_len - 1] == '\n') {
    name_len -= 1;
  }

  flags = 0;
  if (permissions[0] == 'r') {
    flags |= PROT_READ;
  }
  if (permissions[2] == 'x') {
    flags |= PROT_EXEC;
  }

  MapEntry *entry = new MapEntry(start, end, offset, name, name_len, flags);
  if (!(flags & PROT_READ)) {
    // Any unreadable map will just get a zero load bias.
    entry->load_bias = 0;
    entry->init = true;
    entry->valid = false;
  }
  return entry;
}

/**
 * Safely reads a value of type T directly out of this process's own mapped
 * memory at `addr`, used to inspect a loaded library's own ELF header/
 * program headers in place. Bounds- and readability-checks the map entry
 * first since this is a raw pointer dereference into live process memory.
 *
 * 中文：直接从本进程自身已映射内存的 `addr` 处安全读取一个类型为 T 的值，
 * 用于原地查看某个已加载库自身的 ELF 头/程序头。由于这是对存活进程内存
 * 的一次原始指针解引用，因此会先对该 map entry 做边界与可读性检查。
 */
template <typename T>
static inline bool GetVal(MapEntry *entry, uintptr_t addr, T *store) {
  if (!(entry->flags & PROT_READ) || addr < entry->start ||
      addr + sizeof(T) > entry->end) {
    return false;
  }
  // Make sure the address is aligned properly.
  if (addr & (sizeof(T) - 1)) {
    return false;
  }
  *store = *reinterpret_cast<T *>(addr);
  return true;
}

/**
 * Checks whether a mapped region begins with the ELF magic number, i.e.
 * whether this map entry is actually the start of a loaded ELF image (as
 * opposed to some other anonymous/file mapping) before it's treated as one.
 *
 * 中文：检查一段映射区域是否以 ELF 魔数开头，也就是判断这个 map entry
 * 是否真的是一个已加载 ELF 镜像的起始处（而不是其他匿名映射或文件映射），
 * 然后才把它当作 ELF 镜像来处理。
 */
static bool ValidElf(MapEntry *entry) {
  uintptr_t addr = entry->start;
  uintptr_t end;
  if (__builtin_add_overflow(addr, SELFMAG, &end) || end >= entry->end) {
    return false;
  }

  return memcmp(reinterpret_cast<void *>(addr), ELFMAG, SELFMAG) == 0;
}

/**
 * Computes the ELF "load bias" (the delta between a segment's linked vaddr
 * and where it actually ended up mapped in memory) by walking this entry's
 * program headers directly out of the process's own address space. The load
 * bias is needed to convert a raw runtime PC into a stable file offset that
 * symbolizers/addr2line can look up in the on-disk .so.
 *
 * 中文：通过直接在进程自身地址空间中遍历该 map entry 的程序头，计算 ELF
 * 的“加载偏移（load bias）”，即某个 segment 的链接期 vaddr 与它实际被映射
 * 到内存中的位置之间的差值。需要这个加载偏移才能把运行时的原始 PC 换算成
 * 磁盘上 .so 文件中稳定的偏移量，供符号化工具/addr2line 查找使用。
 */
static void ReadLoadbias(MapEntry *entry) {
  entry->load_bias = 0;
  uintptr_t addr = entry->start;
  ElfW(Ehdr) ehdr;
  if (!GetVal<ElfW(Half)>(entry, addr + offsetof(ElfW(Ehdr), e_phnum),
                          &ehdr.e_phnum)) {
    return;
  }
  if (!GetVal<ElfW(Off)>(entry, addr + offsetof(ElfW(Ehdr), e_phoff),
                         &ehdr.e_phoff)) {
    return;
  }
  addr += ehdr.e_phoff;
  for (size_t i = 0; i < ehdr.e_phnum; i++) {
    ElfW(Phdr) phdr;
    if (!GetVal<ElfW(Word)>(entry, addr + offsetof(ElfW(Phdr), p_type),
                            &phdr.p_type)) {
      return;
    }
    if (!GetVal<ElfW(Word)>(entry, addr + offsetof(ElfW(Phdr), p_flags),
                            &phdr.p_flags)) {
      return;
    }
    if (!GetVal<ElfW(Off)>(entry, addr + offsetof(ElfW(Phdr), p_offset),
                           &phdr.p_offset)) {
      return;
    }
    if ((phdr.p_type == PT_LOAD) && (phdr.p_flags & PF_X)) {
      if (!GetVal<ElfW(Addr)>(entry, addr + offsetof(ElfW(Phdr), p_vaddr),
                              &phdr.p_vaddr)) {
        return;
      }
      entry->load_bias = phdr.p_vaddr - phdr.p_offset;
      return;
    }
    addr += sizeof(phdr);
  }
}

/**
 * Lazily validates a MapEntry as an ELF image and computes its load bias
 * exactly once (guarded by entry->init), since both operations dereference
 * live process memory and are only needed the first time a PC lands in this
 * region.
 *
 * 中文：惰性地验证一个 MapEntry 是否是 ELF 镜像，并只计算一次它的加载
 * 偏移（由 entry->init 保护），因为这两个操作都需要解引用存活进程的内存，
 * 只有当第一次有 PC 落在这个区域内时才需要执行。
 */
static void inline Init(MapEntry *entry) {
  if (entry->init) {
    return;
  }
  entry->init = true;
  if (ValidElf(entry)) {
    entry->valid = true;
    ReadLoadbias(entry);
  }
}

/**
 * Reads and parses the whole of /proc/self/maps into the entries_ set. This
 * is the standard, privilege-free way for a process to enumerate its own
 * loaded library ranges on Linux/Android (no ptrace or root needed) — used
 * here to build the lookup table CalculateRelPc() searches.
 *
 * 中文：读取并解析整个 /proc/self/maps 文件，填充进 entries_ 集合。这是
 * Linux/Android 上进程枚举自身已加载库地址范围的标准、无需特殊权限的方式
 * （不需要 ptrace 也不需要 root）——用来构建 CalculateRelPc() 所查询的
 * 查找表。
 */
bool MemoryMap::ReadMaps() {
  // "re": 'e' asks the kernel to set O_CLOEXEC on this fd so it isn't
  // accidentally inherited by any child process this app might fork/exec.
  // 中文："re" 中的 'e' 要求内核为这个 fd 设置 O_CLOEXEC，避免它被本 App
  // 可能 fork/exec 出的子进程意外继承。
  FILE *fp = fopen("/proc/self/maps", "re");
  if (fp == nullptr) {
    return false;
  }

  std::vector<char> buffer(1024);
  while (fgets(buffer.data(), buffer.size(), fp) != nullptr) {
    MapEntry *entry = ParseLine(buffer.data());
    if (entry == nullptr) {
      fclose(fp);
      return false;
    }

    auto it = entries_.find(entry);
    if (it == entries_.end()) {
      entries_.insert(entry);
    } else {
      delete entry;
    }
  }
  fclose(fp);
  return true;
}

/** Frees all cached MapEntry objects owned by this MemoryMap.
 *
 * 中文：释放本 MemoryMap 持有的所有缓存 MapEntry 对象。
 */
MemoryMap::~MemoryMap() {
  for (auto *entry : entries_) {
    delete entry;
  }
  entries_.clear();
}

/**
 * Symbolication step: given a raw backtrace PC captured during the "record"
 * stage, finds which mapped .so it falls in and computes `rel_pc` — the
 * offset within that library (accounting for ELF load bias) that a
 * symbolizer/addr2line would need. Falls back to re-reading
 * /proc/self/maps if the address isn't in the cached table yet (e.g. a
 * library was loaded after the last read).
 *
 * 中文：符号化步骤：给定“record”阶段捕获到的一个原始调用栈 PC，找出它落在
 * 哪个已映射的 .so 中，并计算出 `rel_pc`——即符号化工具/addr2line 所需要
 * 的、该库内部的偏移量（已考虑 ELF 加载偏移）。如果该地址还不在缓存表中
 * （例如某个库是在上一次读取之后才被加载的），会回退为重新读取
 * /proc/self/maps。
 */
MapEntry *MemoryMap::CalculateRelPc(uintptr_t pc, uintptr_t *rel_pc) {
  MapEntry pc_entry(pc);

  auto it = entries_.find(&pc_entry);
  if (it == entries_.end()) {
    ReadMaps();
  }
  it = entries_.find(&pc_entry);
  if (it == entries_.end()) {
    return nullptr;
  }

  MapEntry *entry = *it;
  Init(entry);

  if (rel_pc != nullptr) {
    // Need to check to see if this is a read-execute map and the read-only
    // map is the previous one.
    if (!entry->valid && it != entries_.begin()) {
      MapEntry *prev_entry = *--it;
      if (prev_entry->flags == PROT_READ &&
          prev_entry->offset < entry->offset &&
          prev_entry->name == entry->name) {
        Init(prev_entry);

        if (prev_entry->valid) {
          entry->elf_start_offset = prev_entry->offset;
          *rel_pc = pc - entry->start + entry->offset + prev_entry->load_bias;
          return entry;
        }
      }
    }
    *rel_pc = pc - entry->start + entry->load_bias;
  }
  return entry;
}

/**
 * Formats a human-readable line for one backtrace frame: "<so name>[+offset]
 * (symbol+delta)". Used only when local symbolication is enabled, since it
 * requires the demangling/dladdr lookups below (heavier than just the
 * .so name + numeric offset the caller uses otherwise).
 *
 * 中文：为一帧调用栈格式化出一行可读文本："<so 名称>[+偏移] (符号+增量)"。
 * 仅在启用本地符号化时才会用到，因为它需要下面的反修饰（demangle）/dladdr
 * 查找操作（比调用方在其他情况下直接使用的“.so 名 + 数字偏移”方式要
 * 重得多）。
 */
std::string MemoryMap::FormatSymbol(MapEntry *entry, uintptr_t pc) {
  std::string str;
  uintptr_t offset = 0;
  const char *symbol = nullptr;

  // dladdr resolves which loaded shared object and, if available, which
  // exported symbol a runtime address falls within — a lighter-weight,
  // library-provided alternative to manually walking the ELF symbol table.
  // 中文：dladdr 用于解析一个运行时地址落在哪个已加载的共享库中，以及
  // （如果可用）落在哪个导出符号内——这是标准库提供的一种更轻量的方式，
  // 替代手动遍历 ELF 符号表。
  Dl_info info;
  if (dladdr(reinterpret_cast<void *>(pc), &info) != 0) {
    offset = reinterpret_cast<uintptr_t>(info.dli_saddr);
    symbol = info.dli_sname;
  } else {
    info.dli_fname = nullptr;
  }

  const char *soname =
      (entry != nullptr) ? entry->name.c_str() : info.dli_fname;
  if (soname == nullptr) {
    soname = "<unknown>";
  }

  char offset_buf[128];
  if (entry != nullptr && entry->elf_start_offset != 0) {
    snprintf(offset_buf, sizeof(offset_buf), " (offset 0x%" PRIxPTR ")",
             entry->elf_start_offset);
  } else {
    offset_buf[0] = '\0';
  }

  char buf[1024];
  if (symbol != nullptr) {
    // C++ symbols are Itanium-mangled in the ELF symbol table; demangle back
    // to a readable name (e.g. "Foo::bar(int)") for the leak report.
    // 中文：ELF 符号表中的 C++ 符号是按 Itanium ABI 修饰过的；这里将其反
    // 修饰还原成可读名称（例如 "Foo::bar(int)"），用于泄漏报告展示。
    char *demangled_name =
        abi::__cxa_demangle(symbol, nullptr, nullptr, nullptr);
    const char *name;
    if (demangled_name != nullptr) {
      name = demangled_name;
    } else {
      name = symbol;
    }
    snprintf(buf, sizeof(buf), "  %s%s (%s+%" PRIuPTR ")\n", soname, offset_buf,
             name, pc - offset);
    free(demangled_name);
  } else {
    snprintf(buf, sizeof(buf), "  %s%s\n", soname, offset_buf);
  }
  str += buf;

  return std::move(str);
}
