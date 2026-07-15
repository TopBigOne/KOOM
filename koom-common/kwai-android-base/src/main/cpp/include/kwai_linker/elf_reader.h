// Copyright 2020 Kwai, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//         http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: lbtrace

#ifndef KOOM_KWAI_LINKER_SRC_MAIN_CPP_INCLUDE_ELF_READER_H_
#define KOOM_KWAI_LINKER_SRC_MAIN_CPP_INCLUDE_ELF_READER_H_

#include <link.h>
#include <string>
#include "elf_wrapper.h"

namespace kwai {
namespace linker {
/**
 * Manually parses an ELF file's section headers and symbol tables (.dynsym,
 * .dynstr, .symtab, .strtab, hash sections, .gnu_debugdata) to resolve symbol
 * addresses without going through the system dynamic linker. Exists because
 * Android's linker namespace restrictions block dlopen/dlsym on many internal
 * libraries (e.g. non-NDK libart.so) - this class reimplements just enough of the
 * linker's own ELF-parsing logic to look symbols up anyway. See kwai_dlfcn.h/.cpp
 * for the higher-level dlopen/dlsym-style wrappers built on top of this class.
 *
 * 中文：手动解析 ELF 文件的 section header 和符号表（.dynsym、.dynstr、.symtab、
 * .strtab、hash 相关 section、.gnu_debugdata），从而在不经过系统动态链接器的情况下
 * 解析出符号地址。之所以这样做，是因为 Android 的 linker 命名空间限制会阻止对许多
 * 内部库（例如非 NDK 的 libart.so）调用 dlopen/dlsym —— 这个类重新实现了链接器自身
 * ELF 解析逻辑中足够的部分，从而绕开限制查找符号。更上层的、基于此类构建的
 * dlopen/dlsym 风格封装参见 kwai_dlfcn.h/.cpp。
 */
class ElfReader {
 public:
  // Legacy SHT_HASH (.hash) bucket/chain table layout, used for O(1)-ish dynsym
  // lookup by name on ELFs that don't provide the newer GNU hash section below.
  // 中文：传统的 SHT_HASH（.hash）bucket/chain 表结构，用于在没有提供下面更新的
  // GNU hash section 的 ELF 上，按符号名进行近似 O(1) 的 dynsym 查找。
  struct ElfHash {
    ElfW(Word) nbucket;
    ElfW(Word) nchain;
    ElfW(Word)* bucket;
    ElfW(Word)* chain;
    uint32_t Hash(const uint8_t *name) {
      uint32_t h = 0, g;

      while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
      }

      return h;
    }
  };

  // Modern SHT_GNU_HASH (.gnu.hash) layout, including its bloom filter for fast
  // rejection of non-matching symbol names before walking the bucket/chain table.
  // 中文：现代的 SHT_GNU_HASH（.gnu.hash）结构，包含其布隆过滤器（bloom filter），
  // 可以在遍历 bucket/chain 表之前快速排除不匹配的符号名。
  struct GnuHash {
    ElfW(Word) gnu_nbucket;
    ElfW(Word) gnu_maskwords;
    ElfW(Word) gnu_shift2;
    ElfW(Addr)* gnu_bloom_filter;
    ElfW(Word)* gnu_bucket;
    ElfW(Word)* gnu_chain;
    uint32_t Hash(const uint8_t *name) {
      uint32_t h = 5381;

      while (*name != 0) {
        h += (h << 5) + *name++; // h*33 + c = h + h * 32 + c = h + h << 5 + c
      }
      return h;
    }
  };

  // Wraps an already-mapped/opened ELF image; call Init() before using LookupSymbol().
  // 中文：封装一个已经被映射/打开的 ELF 镜像；使用 LookupSymbol() 之前必须先调用
  // Init()。
  explicit ElfReader(std::shared_ptr<ElfWrapper> elf_wrapper);
  // Checks the ELF magic bytes before any header field is trusted.
  // 中文：在信任任何 header 字段之前，先校验 ELF 魔数（magic bytes）。
  bool IsValidElf();
  // Walks the section header table to locate symbol/string/hash sections - this is
  // the manual equivalent of what the dynamic linker does when it loads a library.
  // 中文：遍历 section header 表以定位符号表、字符串表、hash 相关的 section —— 这是
  // 对动态链接器加载库时所做工作的手动等价实现。
  bool Init();
  /**
   * Lookup symbol address(load_base + symbol vaddr) from the ELF file, if fail return nullptr
   *
   * 1. Lookup symbol from dynsym table using hash/gnu_hash
   * 2. Try read symtab(symtab NOT in loaded segments) from ELF, then linear lookup symbol
   * 3. Try read gnu_debugdata(lZMA compressed ELF) from ELF, then linear lookup symtab
   */
  void *LookupSymbol(const char *symbol, ElfW(Addr) load_base, bool only_dynsym = false);
  ~ElfReader() = default;

 private:
  // Bounds-checked offset->pointer conversion into the mapped ELF image; guards
  // against out-of-bounds reads from a malformed/truncated ELF.
  template<class T>T *CheckedOffset(off_t offset, size_t size);
  bool IsValidRange(off_t offset);
  // Parse the legacy .hash section layout.
  void BuildHash(ElfW(Word) *hash_section);
  // Parse the modern .gnu.hash section layout (bloom filter + buckets/chain).
  void BuildGnuHash(ElfW(Word) *gnu_hash_section);
  // Dynsym lookup via legacy .hash bucket/chain.
  ElfW(Addr) LookupByElfHash(const char *symbol);
  // Dynsym lookup via modern .gnu.hash bloom filter + bucket/chain.
  ElfW(Addr) LookupByGnuHash(const char *symbol);
  // Decompress .gnu_debugdata (XZ-compressed mini ELF with extra symbols) as a
  // last-resort symbol source.
  bool DecGnuDebugdata(std::string &decompressed_data);
  std::shared_ptr<ElfWrapper> elf_wrapper_;
  const ElfW(Shdr)* shdr_table_;
  const ElfW(Sym)* dynsym_;
  const char *dynstr_;
  const ElfW(Sym)* symtab_;
  ElfW(Word) symtab_ent_count_;
  const char *strtab_;
  const char *gnu_debugdata_;
  ElfW(Word) gnu_debugdata_size_;
  ElfHash elf_hash_;
  bool has_elf_hash_;
  GnuHash gnu_hash_;
  bool has_gnu_hash_;
};
} // namespace linker
} // namespace kwai
#endif // KOOM_KWAI_LINKER_SRC_MAIN_CPP_INCLUDE_ELF_READER_H_
