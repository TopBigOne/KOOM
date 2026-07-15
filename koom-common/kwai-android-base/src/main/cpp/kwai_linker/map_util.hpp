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

#include <inttypes.h>
#include <link.h>
#include <log/log.h>
#include <sys/mman.h>

#include <string>
#include <vector>

#if __ANDROID_API__ < 21
extern "C" __attribute__((weak)) int dl_iterate_phdr(
    int (*)(struct dl_phdr_info *, size_t, void *), void *);
#endif

namespace kwai {
namespace linker {
/**
 * Finds where a shared library is actually loaded in this process's address space -
 * its load_bias/load_base and full path - without asking the dynamic linker for a
 * handle to it. Used by DlFcn::dlopen_elf() as the first step before manually
 * parsing that library's ELF sections (see ElfReader), since the namespace-restricted
 * linker may refuse to dlopen() the library at all.
 *
 * 中文：在不向动态链接器索要句柄的情况下，找出一个共享库在当前进程地址空间中
 * 实际的加载位置——它的 load_bias/load_base 以及完整路径。DlFcn::dlopen_elf()
 * 会先调用它作为第一步，然后再手动解析该库的 ELF section（参见 ElfReader），
 * 因为受命名空间限制的链接器可能根本拒绝对该库执行 dlopen()。
 */
class MapUtil {
 public:
  /**
  TECHNICAL NOTE ON ELF LOADING.

  An ELF file's program header table contains one or more PT_LOAD
  segments, which corresponds to portions of the file that need to
  be mapped into the process' address space.

  Each loadable segment has the following important properties:

    p_offset  -> segment file offset
    p_filesz  -> segment file size
    p_memsz   -> segment memory size (always >= p_filesz)
    p_vaddr   -> segment's virtual address
    p_flags   -> segment flags (e.g. readable, writable, executable)
    p_align   -> segment's in-memory and in-file alignment

  We will ignore the p_paddr field of ElfW(Phdr) for now.

  The loadable segments can be seen as a list of [p_vaddr ... p_vaddr+p_memsz)
  ranges of virtual addresses. A few rules apply:

  - the virtual address ranges should not overlap.

  - if a segment's p_filesz is smaller than its p_memsz, the extra bytes
    between them should always be initialized to 0.

  - ranges do not necessarily start or end at page boundaries. Two distinct
    segments can have their start and end on the same page. In this case, the
    page inherits the mapping flags of the latter segment.

  Finally, the real load addrs of each segment is not p_vaddr. Instead the
  loader decides where to load the first segment, then will load all others
  relative to the first one to respect the initial range layout.

  For example, consider the following list:

    [ offset:0,      filesz:0x4000, memsz:0x4000, vaddr:0x30000 ],
    [ offset:0x4000, filesz:0x2000, memsz:0x8000, vaddr:0x40000 ],

  This corresponds to two segments that cover these virtual address ranges:

       0x30000...0x34000
       0x40000...0x48000

  If the loader decides to load the first segment at address 0xa0000000
  then the segments' load address ranges will be:

       0xa0030000...0xa0034000
       0xa0040000...0xa0048000

  In other words, all segments must be loaded at an address that has the same
  constant offset from their p_vaddr value. This offset is computed as the
  difference between the first segment's load address, and its p_vaddr value.

  However, in practice, segments do _not_ start at page boundaries. Since we
  can only memory-map at page boundaries, this means that the bias is
  computed as:

       load_bias = phdr0_load_address - PAGE_START(phdr0->p_vaddr)

  (NOTE: The value must be used as a 32-bit unsigned integer, to deal with
          possible wrap around UINT32_MAX for possible large p_vaddr values).

  And that the phdr0_load_address must start at a page boundary, with
  the segment's real content starting at:

       phdr0_load_address + PAGE_OFFSET(phdr0->p_vaddr)

  Note that ELF requires the following condition to make the mmap()-ing work:

      PAGE_OFFSET(phdr0->p_vaddr) == PAGE_OFFSET(phdr0->p_offset)

  The load_bias must be added to any p_vaddr value read from the ELF file to
  determine the corresponding memory address.

  **/
  /**
   * Get the base address(load_bias) of a loaded so, what is the load_bias?
   * See above ELF LOADING detail.
   *
   * Note: You should using full path name because some libraries have same
   * name.
   */
  static bool GetLoadInfo(const std::string &name, ElfW(Addr) * load_base,
                          std::string &so_full_name, int android_api) {
    // Actually Android 5.x, we can using "dl_iterate_phdr",
    // but we need lock "g_dl_mutex" by self, so we just using maps in
    // Android 5.x.
    auto get_load_info = android_api > __ANDROID_API_L_MR1__
                             ? GetLoadInfoByDl
                             : GetLoadInfoByMaps;
    return get_load_info(name, load_base, so_full_name);
  }

 private:
  struct MapEntry {
    std::string name;
    uintptr_t start;
    uintptr_t end;
    uintptr_t offset;
    int flags;
  };
  using MapEntry = struct MapEntry;

  // Safely read a T-sized value at |addr| out of a mapped region described by
  // |entry|, refusing to read past its bounds or from a non-readable/misaligned
  // address - needed because ReadLoadBias below walks raw ELF header/phdr bytes
  // straight out of process memory rather than through a file API.
  // 中文：从 |entry| 描述的映射区域中安全地读取 |addr| 处一个 T 大小的值，
  // 拒绝越界读取或从不可读/未对齐的地址读取——之所以需要这个函数，是因为下面的
  // ReadLoadBias 是直接从进程内存中读取原始的 ELF header/phdr 字节，而不是
  // 通过文件 API 来读取的。
  template <typename T>
  static inline bool GetVal(MapEntry &entry, uintptr_t addr, T *store) {
    if (!(entry.flags & PROT_READ) || addr < entry.start ||
        addr + sizeof(T) > entry.end) {
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
   * Compute a library's load_bias by reading its ELF header/program headers
   * directly out of an already-mapped memory region (found via /proc/self/maps in
   * GetLoadInfoByMaps), rather than by opening the library file - this variant
   * matters on old Android where dl_iterate_phdr() can't safely be used without
   * taking the linker's internal lock ourselves.
   *
   * 中文：直接从一块已经映射好的内存区域（通过 GetLoadInfoByMaps 中的
   * /proc/self/maps 找到）中读取库的 ELF header/program header，从而计算出
   * 它的 load_bias，而不是打开库文件来读取——这种做法在老版本 Android 上尤为
   * 重要，因为那里如果不自己去持有链接器内部的锁，就无法安全地调用
   * dl_iterate_phdr()。
   */
  static bool ReadLoadBias(MapEntry &entry, ElfW(Addr) * load_bias) {
    uintptr_t addr = entry.start;
    ElfW(Ehdr) ehdr;
    if (!GetVal<ElfW(Half)>(entry, addr + offsetof(ElfW(Ehdr), e_phnum),
                            &ehdr.e_phnum)) {
      return false;
    }
    if (!GetVal<ElfW(Off)>(entry, addr + offsetof(ElfW(Ehdr), e_phoff),
                           &ehdr.e_phoff)) {
      return false;
    }
    addr += ehdr.e_phoff;
    for (size_t i = 0; i < ehdr.e_phnum; i++) {
      ElfW(Phdr) phdr;
      if (!GetVal<ElfW(Word)>(entry, addr + offsetof(ElfW(Phdr), p_type),
                              &phdr.p_type)) {
        return false;
      }
      if (!GetVal<ElfW(Word)>(entry, addr + offsetof(ElfW(Phdr), p_flags),
                              &phdr.p_flags)) {
        return false;
      }
      if (!GetVal<ElfW(Off)>(entry, addr + offsetof(ElfW(Phdr), p_offset),
                             &phdr.p_offset)) {
        return false;
      }

      if ((phdr.p_type == PT_LOAD) && (phdr.p_flags & PF_X)) {
        if (!GetVal<ElfW(Addr)>(entry, addr + offsetof(ElfW(Phdr), p_vaddr),
                                &phdr.p_vaddr)) {
          return false;
        }
        *load_bias = phdr.p_vaddr;
        return true;
      }
      addr += sizeof(phdr);
    }
    return false;
  }

  // Simple suffix match, used below to match a library's full mapped path against
  // the (possibly bare) name the caller asked for.
  // 中文：简单的后缀匹配，用于将一个库的完整映射路径与调用方传入的（可能是
  // 裸文件名的）名字进行匹配。
  static bool EndsWith(const char *target, const char *suffix) {
    if (!target || !suffix) {
      return false;
    }
    const char *sub_str = strstr(target, suffix);
    return sub_str && strlen(sub_str) == strlen(suffix);
  }

  /**
   * Find a loaded library's load_base by scanning this process's own memory map
   * (/proc/self/maps) rather than asking the dynamic linker - used on API levels
   * where calling dl_iterate_phdr() ourselves isn't safe (see GetLoadInfo() comment)
   * or as a fallback everywhere else. /proc/self/maps is the same kernel-exposed,
   * no-privilege-needed mechanism used elsewhere in KOOM for inspecting a process's
   * memory layout (see process_map.cpp).
   *
   * 中文：通过扫描本进程自己的内存映射（/proc/self/maps）来查找一个已加载库的
   * load_base，而不是询问动态链接器——用于那些自己调用 dl_iterate_phdr()
   * 不安全的 API 级别（见 GetLoadInfo() 的注释），或者作为其他情况下的兜底方案。
   * /proc/self/maps 与 KOOM 中其他地方（见 process_map.cpp）用来检查进程内存
   * 布局的机制是同一个——都是内核暴露的、无需特殊权限即可访问的方式。
   */
  static bool GetLoadInfoByMaps(const std::string &name, ElfW(Addr) * load_base,
                                std::string &full_name) {
    // fopen (buffered stdio) on /proc/self/maps: this pseudo-file is generated by the
    // kernel on read, exposing this process's own segment list as plain text.
    // 中文：以带缓冲的 stdio 方式（fopen）打开 /proc/self/maps：这个伪文件是内核
    // 在被读取时动态生成的，以纯文本形式暴露本进程自身的内存段列表。
    FILE *fp = fopen("/proc/self/maps", "re");
    auto ret = false;
    if (fp == nullptr) {
      return ret;
    }

    auto parse_line = [](char *map_line, MapEntry &curr_entry,
                         int &name_pos) -> bool {
      char permissions[5];
      if (sscanf(map_line,
                 "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %*x:%*x %*d %n",
                 &curr_entry.start, &curr_entry.end, permissions,
                 &curr_entry.offset, &name_pos) < 4) {
        return false;
      }
      curr_entry.flags = 0;
      if (permissions[0] == 'r') {
        curr_entry.flags |= PROT_READ;
      }
      if (permissions[2] == 'x') {
        curr_entry.flags |= PROT_EXEC;
      }
      return true;
    };
    std::vector<char> buffer(1024);
    MapEntry prev_entry = {};
    // Read /proc/self/maps one line at a time; each line describes one mapped
    // region (address range, permissions, offset, backing file) in the same format
    // documented/parsed in process_map.h's ReadMapFileContent().
    // 中文：逐行读取 /proc/self/maps；每一行描述一个映射区域（地址范围、权限、
    // 偏移量、对应的后备文件），格式与 process_map.h 中 ReadMapFileContent()
    // 所记录/解析的格式相同。
    while (fgets(buffer.data(), buffer.size(), fp) != nullptr) {
      MapEntry curr_entry = {};
      int name_pos;

      if (!parse_line(buffer.data(), curr_entry, name_pos)) {
        continue;
      }

      const char *map_name = buffer.data() + name_pos;
      size_t name_len = strlen(map_name);
      if (name_len && map_name[name_len - 1] == '\n') {
        name_len -= 1;
      }

      curr_entry.name = std::string(map_name, name_len);
      if (curr_entry.flags == PROT_NONE) {
        continue;
      }

      // If an (readable-)executable map offset NOT equal 0, need check previous
      // readable map
      if ((curr_entry.flags & PROT_EXEC) == PROT_EXEC &&
          EndsWith(curr_entry.name.c_str(), name.c_str())) {
        ElfW(Addr) load_bias;
        if (curr_entry.offset == 0) {
          ret = ReadLoadBias(curr_entry, &load_bias);
        } else {
          if (EndsWith(prev_entry.name.c_str(), name.c_str()) &&
              prev_entry.offset == 0 && prev_entry.flags == PROT_READ) {
            ret = ReadLoadBias(prev_entry, &load_bias);
          }
        }

        if (ret) {
          *load_base = curr_entry.start - load_bias;
          full_name = curr_entry.name;
          break;
        }
      }
      prev_entry = curr_entry;
    }
    fclose(fp);
    return ret;
  }

  /**
   * Find a loaded library's load_base via the system's dl_iterate_phdr(), which asks
   * the dynamic linker directly for its already-computed load addresses - cheaper
   * and more reliable than scanning /proc/self/maps by hand, so this is preferred
   * on API levels where it's safe to call (see GetLoadInfo()'s Android 5.x note).
   *
   * 中文：借助系统的 dl_iterate_phdr() 查找已加载库的 load_base，它直接向动态
   * 链接器询问其已经计算好的加载地址——比手动扫描 /proc/self/maps 更廉价、更
   * 可靠，因此在可以安全调用它的 API 级别上（参见 GetLoadInfo() 中关于
   * Android 5.x 的说明）优先使用这种方式。
   */
  static bool GetLoadInfoByDl(const std::string &name, ElfW(Addr) * load_base,
                              std::string &so_full_name) {
    struct PhdrInfo {
      const char *name;
      std::string full_name;
      ElfW(Addr) load_base;
      off_t load_bias;
    };
    PhdrInfo phdr_info = {
        .name = name.c_str(), .full_name = "", .load_base = 0};
    auto iterate_phdr_callback = [](struct dl_phdr_info *phdr_info, size_t size,
                                    void *data) -> int {
      PhdrInfo *info = reinterpret_cast<PhdrInfo *>(data);
      if (!phdr_info->dlpi_name) {
        ALOGW("dlpi_name nullptr");
        return 0;
      }
      const char *sub_str = strstr(phdr_info->dlpi_name, info->name);
      if (sub_str && strlen(sub_str) == strlen(info->name)) {
        info->load_base = phdr_info->dlpi_addr;
        info->full_name = phdr_info->dlpi_name;
        return 1;
      }
      return 0;
    };

    // dl_iterate_phdr() asks the dynamic linker to walk its own list of currently
    // loaded modules and invoke our callback for each - this is the "legitimate"
    // linker API for discovering load addresses, used here instead of touching
    // /proc/self/maps whenever it's safe to call.
    // 中文：dl_iterate_phdr() 会请求动态链接器遍历它自身维护的当前已加载模块
    // 列表，并对每一个模块调用我们的回调——这是发现加载地址的“正规”链接器 API，
    // 只要能安全调用，这里就优先使用它而不是直接读取 /proc/self/maps。
    dl_iterate_phdr(iterate_phdr_callback,
                    reinterpret_cast<void *>(&phdr_info));
    if (!phdr_info.load_base) {
      return false;
    }

    *load_base = phdr_info.load_base;
    so_full_name = phdr_info.full_name;
    return true;
  }
};
}  // namespace linker
}  // namespace kwai
