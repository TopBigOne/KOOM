/*
 * Copyright (c) 2020. Kwai, Inc. All rights reserved.
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
 * Created by Qiushi Xue <xueqiushi@kuaishou.com> on 2020.
 *
 */

#ifndef KWAI_DLFCN_H
#define KWAI_DLFCN_H

#include <link.h>
#include <string>

namespace kwai {
namespace linker {

/**
 * Wrappers that let KOOM resolve symbols from libraries which Android's restricted
 * dynamic linker namespaces would normally hide from a regular dlopen()/dlsym() call
 * (e.g. non-NDK internal libraries such as libart.so). Two distinct strategies are
 * offered:
 *  - dlopen/dlsym/dlclose: still goes through parts of the system linker
 *    (__loader_dlopen / dl_iterate_phdr) but sidesteps the namespace check itself;
 *    cheaper, but limited to what that approach can reach on each API level.
 *  - dlopen_elf/dlsym_elf/dlclose_elf: never touches the system linker at all -
 *    locates the library's load address via /proc/self/maps and parses its ELF
 *    sections directly (see ElfReader); more expensive, but works even where the
 *    lighter-weight approach above is blocked, and can also resolve LOCAL/.symtab
 *    symbols that .dynsym-only lookups (i.e. real dlsym()) can never return.
 *
 * 中文：这里提供的封装函数，能让 KOOM 解析出那些原本会被 Android 受限的动态链接器
 * 命名空间机制隐藏、无法通过常规 dlopen()/dlsym() 获取的库中的符号（例如非 NDK 的
 * 内部库 libart.so）。提供了两种不同的策略：
 *  - dlopen/dlsym/dlclose：仍然会经过系统链接器的部分流程
 *    （__loader_dlopen / dl_iterate_phdr），但绕开了命名空间检查本身；成本较低，
 *    但能力上限取决于该方式在各个 API 版本上能够触达的范围。
 *  - dlopen_elf/dlsym_elf/dlclose_elf：完全不经过系统链接器——通过
 *    /proc/self/maps 定位库的加载地址，然后直接解析其 ELF section（参见
 *    ElfReader）；开销更大，但即使上面轻量级的方式被阻挡也依然可用，并且还能
 *    解析出仅依赖 .dynsym 的查找（即真正的 dlsym()）永远无法返回的
 *    LOCAL/.symtab 符号。
 */
class DlFcn {
 public:
  struct SoDlInfo {
    /**
     * The full path name of so
     */
    std::string full_name;
    /**
     * The load base address. For example:
     * phdr0: the PT_LOAD segment
     * phdr0_load_address: the segment map start address.
     * phdr0->p_vaddr: the segment virtual address.
     *
     * load_base = phdr0_load_address - PAGE_START(phdr0->p_vaddr)
     */
    ElfW(Addr) load_base;
  };

  /**
   * Android N+ dlopen bypass
   */
  static void *dlopen(const char *lib_name, int flags);

  /**
   * Android N+ dlsym bypass
   */
  static void *dlsym(void *handle, const char *name);

  /**
   * Android N+ dlclose bypass
   */
  static int dlclose(void *handle);
  /**
   * Inspired by https://github.com/avs333/Nougat_dlfunctions/
   *
   * Parse ELF file based on /proc/<pid>/mappings and store .dynsym、.dynstr、.symtab、.strtab
   * information.
   *
   * It's much less effective than DlFcn::dlopen, do not use this in low
   * memory state or high performance sensitive scenario!
   *
   * It's more powerful than DlFcn::dlopen which can only get symbols in .dynsym(GLOBAL), it can
   * also get symbols in .symtab(LOCAL).
   */
  static void *dlopen_elf(const char *lib_name, int flags);

  /**
   * Since dlopen_elf consumes more memory, when fetching multiple symbols in a so, try to open
   * it only once, get all symbol addresses and cache them and then close it.
   */
  static void *dlsym_elf(void *handle, const char *name);

  /**
   * Release memroy.
   */
  static int dlclose_elf(void *handle);

  struct dl_iterate_data {
    dl_phdr_info info_;
  };

  static int android_api_;

 private:
  static void init_api();
};

} // namespace linker

} // namespace kwai

#endif // KWAI_DLFCN_H