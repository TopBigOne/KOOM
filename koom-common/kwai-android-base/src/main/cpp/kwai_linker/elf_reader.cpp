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

#include "kwai_linker/elf_reader.h"

#include <7zCrc.h>
#include <Xz.h>
#include <XzCrc64.h>
#include <fcntl.h>
#include <log/log.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

namespace kwai {
namespace linker {
// Section names we need to locate manually, because Android's dynamic linker keeps
// its own resolved copies of these tables private - it doesn't expose an API to walk
// a library's .dynsym/.dynstr/.symtab/.strtab from outside, and namespace-restricted
// libraries (e.g. non-NDK internal libart.so) can't be dlopen()'d at all. This class
// re-implements the linker's ELF section parsing so KOOM can resolve symbols the
// normal dlopen/dlsym path would refuse to give us.
// 中文：这里需要手动定位这些 section 名称，因为 Android 动态链接器把这些表的解析
// 结果私有化了——它没有对外提供遍历某个库 .dynsym/.dynstr/.symtab/.strtab 的 API，
// 并且命名空间受限的库（例如非 NDK 的内部库 libart.so）根本无法被 dlopen()。这个
// 类重新实现了链接器对 ELF section 的解析逻辑，使 KOOM 能够解析出正常
// dlopen/dlsym 路径拒绝提供的符号。
static const char *kDynstrName = ".dynstr";
static const char *kStrtabName = ".strtab";
static const char *kGnuHash = ".gnu.hash";
// .gnu_debugdata holds an XZ/LZMA-compressed mini ELF containing symbols stripped
// from the main binary to save space; some symbols only exist there.
// 中文：.gnu_debugdata 保存的是一个经过 XZ/LZMA 压缩的迷你 ELF，里面存放着为节省
// 体积而从主二进制中剥离出去的符号；有些符号只能在这里面找到。
static const char *kGnuDebugdata = ".gnu_debugdata";

/**
 * Wrap an already-mapped/opened ELF image (file or in-memory) so its section
 * headers and symbol tables can be parsed without going through the dynamic linker.
 *
 * 中文：包装一个已经映射/打开的 ELF 镜像（文件或内存中的数据），使其 section
 * header 和符号表可以在不经过动态链接器的情况下被解析。
 */
ElfReader::ElfReader(std::shared_ptr<ElfWrapper> elf_wrapper)
    : elf_wrapper_(),
      shdr_table_(nullptr),
      dynsym_(nullptr),
      dynstr_(nullptr),
      symtab_(nullptr),
      symtab_ent_count_(0),
      strtab_(nullptr),
      gnu_debugdata_(nullptr),
      gnu_debugdata_size_(0),
      has_elf_hash_(false),
      has_gnu_hash_(false) {
  if (!elf_wrapper->IsValid()) {
    return;
  }
  elf_wrapper_ = elf_wrapper;
}

/**
 * Check the ELF magic bytes to make sure the wrapped image is actually an ELF file
 * before we start trusting offsets out of its header.
 *
 * 中文：校验 ELF 魔数（magic bytes），确保被包装的镜像确实是一个 ELF 文件，
 * 之后才能放心信任其 header 中的各种偏移量。
 */
bool ElfReader::IsValidElf() {
  return elf_wrapper_ != nullptr &&
         !memcmp(elf_wrapper_->Start()->e_ident, ELFMAG, SELFMAG);
}

/**
 * Manually walk the ELF section header table to locate the symbol/string tables
 * (.dynsym, .dynstr, .symtab, .strtab), hash sections, and .gnu_debugdata. This is
 * exactly what the dynamic linker does internally when loading a library, but done
 * here in userspace so we can resolve symbols in libraries the linker's namespace
 * restrictions would otherwise hide from dlopen/dlsym (e.g. internal libart.so).
 *
 * 中文：手动遍历 ELF section header 表，定位符号表/字符串表
 * （.dynsym、.dynstr、.symtab、.strtab）、哈希 section 以及 .gnu_debugdata。
 * 这与动态链接器加载库时内部所做的事情完全一样，只是这里是在用户态完成的，
 * 从而能够解析出那些被链接器命名空间限制而无法通过 dlopen/dlsym 拿到的库
 * （例如内部的 libart.so）中的符号。
 */
bool ElfReader::Init() {
  if (!IsValidElf() || !IsValidRange(elf_wrapper_->Start()->e_ehsize)) {
    return false;
  }

  // Section header table location/size come straight from the ELF header;
  // CheckedOffset() bounds-checks against the mapped image size before dereferencing.
  // 中文：section header 表的位置和大小直接来自 ELF header；CheckedOffset()
  // 在真正解引用之前会先对照映射镜像的大小做边界检查。
  shdr_table_ = CheckedOffset<ElfW(Shdr)>(
      elf_wrapper_->Start()->e_shoff,
      (elf_wrapper_->Start()->e_shnum) * (elf_wrapper_->Start()->e_shentsize));
  if (!shdr_table_) {
    return false;
  }

  // e_shstrndx points at the section-header-string-table section, whose contents
  // are the NUL-terminated names of every other section (so ".dynstr" etc. below
  // are looked up as byte offsets into this blob rather than by any linker API).
  // 中文：e_shstrndx 指向 section-header-string-table 这个 section，其内容是
  // 所有其他 section 以 NUL 结尾的名字（因此下面的 ".dynstr" 等名字都是通过在这块
  // 数据里查字节偏移得到的，而不是借助任何链接器 API）。
  const char *shstr = CheckedOffset<const char>(
      shdr_table_[elf_wrapper_->Start()->e_shstrndx].sh_offset,
      shdr_table_[elf_wrapper_->Start()->e_shstrndx].sh_size);
  if (!shstr) {
    return false;
  }

  // Classify every section by sh_type/name to find the tables we need; this mirrors
  // the section-processing the linker performs when it maps a library, but we keep
  // pointers to raw file/mmap offsets instead of using the linker's own symbol
  // resolution.
  // 中文：按 sh_type/名称对每个 section 分类，找到我们需要的表；这与链接器映射
  // 一个库时所做的 section 处理过程是一致的，只不过我们保存的是指向原始文件/
  // mmap 偏移的指针，而不是使用链接器自身的符号解析结果。
  for (int index = 0; index < elf_wrapper_->Start()->e_shnum; ++index) {
    if (shdr_table_[index].sh_size <= 0) {
      continue;
    }
    switch (shdr_table_[index].sh_type) {
      case SHT_DYNSYM:
        // .dynsym: the dynamic symbol table (exported/imported symbols) that the
        // linker itself would normally consult for dlsym() lookups.
        // 中文：.dynsym 是动态符号表（导出/导入的符号），链接器本身在处理
        // dlsym() 查询时通常查阅的就是这张表。
        dynsym_ = CheckedOffset<ElfW(Sym)>(shdr_table_[index].sh_offset,
                                           shdr_table_[index].sh_size);
        break;
      case SHT_STRTAB: {
        const char *tmp_str = CheckedOffset<const char>(
            shdr_table_[index].sh_offset, shdr_table_[index].sh_size);
        if (!strcmp(shstr + shdr_table_[index].sh_name, kDynstrName)) {
          // .dynstr: string storage for .dynsym symbol names.
          // 中文：.dynstr 用于存放 .dynsym 中符号名称对应的字符串。
          dynstr_ = tmp_str;
        } else if (!strcmp(shstr + shdr_table_[index].sh_name, kStrtabName)) {
          // .strtab: string storage for .symtab symbol names.
          // 中文：.strtab 用于存放 .symtab 中符号名称对应的字符串。
          strtab_ = tmp_str;
        }
        break;
      }
      case SHT_SYMTAB:
        // .symtab: the full (often stripped-at-runtime) symbol table, including
        // local/internal symbols that .dynsym does NOT expose and that dlsym()
        // can never return - this is why this manual reader is more powerful than
        // the system dlopen/dlsym for resolving internal symbols.
        // 中文：.symtab 是完整的符号表（运行时往往会被 strip 掉），其中包含
        // .dynsym 不会暴露、dlsym() 也永远无法返回的 local/内部符号——这正是
        // 这个手动解析器在解析内部符号时比系统 dlopen/dlsym 更强大的原因。
        symtab_ = CheckedOffset<ElfW(Sym)>(shdr_table_[index].sh_offset,
                                           shdr_table_[index].sh_size);
        symtab_ent_count_ =
            shdr_table_[index].sh_size / shdr_table_[index].sh_entsize;
        break;
      case SHT_HASH:
        // Legacy ELF hash table (.hash) for fast dynsym lookup by name.
        // 中文：传统的 ELF 哈希表（.hash），用于按名字快速查找 dynsym。
        BuildHash(CheckedOffset<ElfW(Word)>(shdr_table_[index].sh_offset,
                                            shdr_table_[index].sh_size));
        break;
      case SHT_PROGBITS:
        if (!strcmp(shstr + shdr_table_[index].sh_name, kGnuDebugdata)) {
          // .gnu_debugdata: compressed mini-ELF with extra symbols; decompressed
          // lazily in DecGnuDebugdata() only if a direct lookup above misses.
          // 中文：.gnu_debugdata 是包含额外符号的压缩迷你 ELF；只有在上面的
          // 直接查找都没命中时，才会在 DecGnuDebugdata() 中惰性解压它。
          gnu_debugdata_ = CheckedOffset<const char>(
              shdr_table_[index].sh_offset, shdr_table_[index].sh_size);
          gnu_debugdata_size_ = shdr_table_[index].sh_size;
        }
        break;
      default:
        if (!strcmp(shstr + shdr_table_[index].sh_name, kGnuHash)) {
          // Modern GNU hash table (.gnu.hash), preferred over .hash when present.
          // 中文：现代的 GNU 哈希表（.gnu.hash），存在时优先于 .hash 使用。
          BuildGnuHash(CheckedOffset<ElfW(Word)>(shdr_table_[index].sh_offset,
                                                 shdr_table_[index].sh_size));
        }
        break;
    }
  }
  return true;
}

/**
 * Resolve |symbol|'s runtime address within a library already mapped at |load_base|,
 * without calling the system dlsym(). Falls through three strategies (dynsym+hash,
 * then symtab linear scan, then compressed gnu_debugdata) so callers can find
 * symbols the restricted dynamic linker would refuse to hand back via dlopen/dlsym.
 *
 * 中文：在不调用系统 dlsym() 的情况下，解析 |symbol| 在已加载于 |load_base| 的
 * 库中的运行时地址。依次尝试三种策略（dynsym+hash 查找，然后是 symtab 线性
 * 扫描，最后是压缩的 gnu_debugdata），使调用方能够找到那些命名空间受限的
 * 动态链接器通过 dlopen/dlsym 拒绝返回的符号。
 */
void *ElfReader::LookupSymbol(const char *symbol, ElfW(Addr) load_base,
                              bool only_dynsym) {
  if (!symbol) {
    return nullptr;
  }

  // First lookup from dynsym using hash
  ElfW(Addr) sym_vaddr =
      has_gnu_hash_ ? LookupByGnuHash(symbol) : LookupByElfHash(symbol);
  if (sym_vaddr != 0) {
    return reinterpret_cast<void *>(load_base + sym_vaddr);
  }

  if (only_dynsym) {
    return nullptr;
  }

  // Try lookup from symtab
  for (int index = 0; index < symtab_ent_count_; index++) {
    // Only care functions and objects
    if (ELF_ST_TYPE(symtab_[index].st_info) != STT_FUNC &&
        ELF_ST_TYPE(symtab_[index].st_info) != STT_OBJECT) {
      continue;
    }

    if (!strcmp(strtab_ + symtab_[index].st_name, symbol)) {
      return reinterpret_cast<void *>(load_base + symtab_[index].st_value);
    }
  }

  // Try lookup from compressed gnu_debugdata
  std::string decompressed_data;
  if (DecGnuDebugdata(decompressed_data)) {
    ElfReader elf_reader(std::make_shared<MemoryElfWrapper>(decompressed_data));
    if (elf_reader.Init()) {
      return elf_reader.LookupSymbol(symbol, load_base);
    }
  }
  return nullptr;
}

/**
 * Turn a file/section offset into a live pointer into the mapped ELF image, after
 * validating the [offset, offset+size) range doesn't run past the mapping - since
 * we're trusting raw values taken straight from the ELF headers, this bounds check
 * is what keeps a malformed/truncated ELF from causing an out-of-bounds read.
 *
 * 中文：将一个文件/section 偏移转换为指向已映射 ELF 镜像的有效指针，前提是先
 * 校验 [offset, offset+size) 区间没有越出映射范围——由于我们直接信任从 ELF
 * header 中取出的原始数值，正是这个边界检查防止了一个畸形/被截断的 ELF
 * 引发越界读取。
 */
template <class T>
T *ElfReader::CheckedOffset(off_t offset, size_t size) {
  if (!IsValidRange(offset + size)) {
    ALOGE("illegal offset %lld, ELF start is %p", offset,
          elf_wrapper_->Start());
    return nullptr;
  }
  return reinterpret_cast<T *>(
      reinterpret_cast<ElfW(Addr)>(elf_wrapper_->Start()) + offset);
}

/**
 * True if |offset| still falls within the bounds of the mapped/read ELF image.
 *
 * 中文：判断 |offset| 是否仍在已映射/已读取的 ELF 镜像范围之内。
 */
bool ElfReader::IsValidRange(off_t offset) {
  return offset <= elf_wrapper_->Size();
}

/**
 * Parse the legacy SHT_HASH (.hash) section layout into elf_hash_ so LookupByElfHash
 * can do O(1)-ish bucket/chain lookups instead of a linear scan over dynsym.
 *
 * 中文：将传统的 SHT_HASH（.hash）section 布局解析到 elf_hash_ 中，使
 * LookupByElfHash 能够进行近似 O(1) 的 bucket/chain 查找，而不必对 dynsym
 * 做线性扫描。
 */
void ElfReader::BuildHash(ElfW(Word) * hash_section) {
  if (!hash_section) {
    return;
  }

  elf_hash_.nbucket = hash_section[0];
  elf_hash_.nchain = hash_section[1];
  elf_hash_.bucket = hash_section + 2;
  elf_hash_.chain = hash_section + 2 + elf_hash_.nbucket;
  has_elf_hash_ = true;
}

/**
 * Parse the modern SHT_GNU_HASH (.gnu.hash) section layout into gnu_hash_, including
 * its bloom filter, so LookupByGnuHash can cheaply reject most non-matching names.
 *
 * 中文：将现代的 SHT_GNU_HASH（.gnu.hash）section 布局（包括其布隆过滤器）
 * 解析到 gnu_hash_ 中，使 LookupByGnuHash 能够以很低的代价排除掉大多数
 * 不匹配的名字。
 */
void ElfReader::BuildGnuHash(ElfW(Word) * gnu_hash_section) {
  if (!gnu_hash_section) {
    return;
  }

  gnu_hash_.gnu_nbucket = gnu_hash_section[0];
  gnu_hash_.gnu_maskwords = gnu_hash_section[2];
  gnu_hash_.gnu_shift2 = gnu_hash_section[3];
  gnu_hash_.gnu_bloom_filter =
      reinterpret_cast<ElfW(Addr) *>(gnu_hash_section + 4);
  gnu_hash_.gnu_bucket = reinterpret_cast<ElfW(Word) *>(
      gnu_hash_.gnu_bloom_filter + gnu_hash_.gnu_maskwords);
  gnu_hash_.gnu_chain =
      gnu_hash_.gnu_bucket + gnu_hash_.gnu_nbucket - gnu_hash_section[1];
  gnu_hash_.gnu_maskwords--;
  has_gnu_hash_ = true;
}

/**
 * Look up |symbol| in .dynsym using the legacy .hash bucket/chain table.
 *
 * 中文：使用传统的 .hash bucket/chain 表在 .dynsym 中查找 |symbol|。
 */
// Hash Only search dynsym and we ignore symbol version check
ElfW(Addr) ElfReader::LookupByElfHash(const char *symbol) {
  if (!has_elf_hash_ || !dynsym_ || !dynstr_) {
    ALOGW("ELF Hash miss or check dynsym/dynstr");
    return 0;
  }
  uint32_t hash = elf_hash_.Hash(reinterpret_cast<const uint8_t *>(symbol));
  for (uint32_t n = elf_hash_.bucket[hash % elf_hash_.nbucket]; n != 0;
       n = elf_hash_.chain[n]) {
    const ElfW(Sym) *sym = dynsym_ + n;
    if (strcmp(dynstr_ + sym->st_name, symbol) == 0) {
      // TODO add log
      return sym->st_value;
    }
  }
  return 0;
}

/**
 * Look up |symbol| in .dynsym using the modern .gnu.hash bloom filter + bucket/chain
 * table (faster rejection of non-matches than the legacy ELF hash).
 *
 * 中文：使用现代的 .gnu.hash 布隆过滤器 + bucket/chain 表在 .dynsym 中查找
 * |symbol|（相比传统 ELF hash，能更快地排除不匹配项）。
 */
// Gnu hash Only search dynsym and we ignore symbol version check
ElfW(Addr) ElfReader::LookupByGnuHash(const char *symbol) {
  if (!has_gnu_hash_ || !dynsym_ || !dynstr_) {
    return 0;
  }

  uint32_t hash = gnu_hash_.Hash(reinterpret_cast<const uint8_t *>(symbol));
  constexpr uint32_t kBloomMaskBits = sizeof(ElfW(Addr)) * 8;
  const uint32_t word_num = (hash / kBloomMaskBits) & gnu_hash_.gnu_maskwords;
  const ElfW(Addr) bloom_word = gnu_hash_.gnu_bloom_filter[word_num];
  const uint32_t h1 = hash % kBloomMaskBits;
  const uint32_t h2 = (hash >> gnu_hash_.gnu_shift2) % kBloomMaskBits;
  // test against bloom filter
  if ((1 & (bloom_word >> h1) & (bloom_word >> h2)) == 0) {
    return 0;
  }
  // bloom test says "probably yes"...
  uint32_t n = gnu_hash_.gnu_bucket[hash % gnu_hash_.gnu_nbucket];

  do {
    const ElfW(Sym) *sym = dynsym_ + n;
    if (((gnu_hash_.gnu_chain[n] ^ hash) >> 1) == 0 &&
        strcmp(dynstr_ + sym->st_name, symbol) == 0) {
      return sym->st_value;
    }
  } while ((gnu_hash_.gnu_chain[n++] & 1) == 0);
  return 0;
}

/**
 * Decompress the .gnu_debugdata section (an XZ-compressed mini ELF holding symbols
 * stripped from the main binary) into |decompressed_data| so it can be re-parsed as
 * its own ElfReader. Only invoked as a last resort when dynsym/symtab lookups miss.
 *
 * 中文：将 .gnu_debugdata section（一个存放着从主二进制中剥离出的符号、经 XZ
 * 压缩的迷你 ELF）解压到 |decompressed_data| 中，以便作为一个独立的 ElfReader
 * 重新解析。仅在 dynsym/symtab 查找都未命中时，作为最后手段被调用。
 */
bool ElfReader::DecGnuDebugdata(std::string &decompressed_data) {
  if (!gnu_debugdata_ || gnu_debugdata_size_ <= 0) {
    ALOGW("%s null or size %d", kGnuDebugdata, gnu_debugdata_size_);
    return false;
  }
  ISzAlloc alloc;
  CXzUnpacker state;
  alloc.Alloc = [](ISzAllocPtr, size_t size) -> void * { return malloc(size); };
  alloc.Free = [](ISzAllocPtr, void *address) -> void { free(address); };
  XzUnpacker_Construct(&state, &alloc);
  CrcGenerateTable();
  Crc64GenerateTable();
  size_t src_offset = 0;
  size_t dst_offset = 0;
  std::string dst(gnu_debugdata_size_, ' ');

  ECoderStatus status = CODER_STATUS_NOT_FINISHED;
  while (status == CODER_STATUS_NOT_FINISHED) {
    dst.resize(dst.size() * 2);
    size_t src_remaining = gnu_debugdata_size_ - src_offset;
    size_t dst_remaining = dst.size() - dst_offset;
    int res = XzUnpacker_Code(
        &state, reinterpret_cast<Byte *>(&dst[dst_offset]), &dst_remaining,
        reinterpret_cast<const Byte *>(gnu_debugdata_ + src_offset),
        &src_remaining, true, CODER_FINISH_ANY, &status);
    if (res != SZ_OK) {
      ALOGE("LZMA decompression failed with error %d", res);
      XzUnpacker_Free(&state);
      return false;
    }
    src_offset += src_remaining;
    dst_offset += dst_remaining;
  }
  XzUnpacker_Free(&state);
  if (!XzUnpacker_IsStreamWasFinished(&state)) {
    ALOGE("LZMA decompresstion failed due to incomplete stream");
    return false;
  }
  dst.resize(dst_offset);
  decompressed_data = std::move(dst);
  return true;
}
}  // namespace linker
}  // namespace kwai