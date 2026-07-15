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

#include <dlfcn.h>
#include <fcntl.h>
#include <kwai_linker/elf_reader.h>
#include <kwai_linker/kwai_dlfcn.h>
#include <kwai_util/kwai_macros.h>
#include <link.h>
#include <log/kcheck.h>
#include <log/log.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

#include "map_util.hpp"

#define LOG_TAG "kwai_dlfcn"

// This file provides two independent bypasses around Android's restricted dynamic
// linker namespaces (which block dlopen/dlsym on non-NDK/internal libraries such as
// libart.so from apps):
//  1. DlFcn::dlopen/dlsym/dlclose - reimplements the old (pre-linker-namespace)
//     lookup behavior on top of the system's own __loader_dlopen / dl_iterate_phdr,
//     for API levels where the namespace restriction can still be routed around.
//  2. DlFcn::dlopen_elf/dlsym_elf/dlclose_elf - a from-scratch path that never calls
//     into the system linker at all: it finds the library's load address via
//     /proc/self/maps (MapUtil) and parses its ELF sections directly (ElfReader),
//     so it works even where the namespace-restricted linker path is fully blocked.
// 中文：本文件提供两种相互独立的手段，用来绕开 Android 受限的动态链接器命名空间
// （该限制会阻止 App 对非 NDK/内部库，例如 libart.so，调用 dlopen/dlsym）：
//  1. DlFcn::dlopen/dlsym/dlclose——在系统自身的 __loader_dlopen / dl_iterate_phdr
//     基础上，重新实现了链接器命名空间限制出现之前的旧查找行为，适用于命名空间
//     限制仍可被绕过的 API 级别。
//  2. DlFcn::dlopen_elf/dlsym_elf/dlclose_elf——一条完全从零实现、根本不调用系统
//     链接器的路径：通过 /proc/self/maps（MapUtil）找到库的加载地址，再直接解析
//     其 ELF section（ElfReader），因此即便命名空间限制的链接器路径被完全封死，
//     它依然可以工作。
namespace kwai {
namespace linker {

// Guards against very old NDK headers where dl_iterate_phdr might not be declared/
// linkable; calling through this wrapper avoids a hard link-time dependency.
// 中文：防范非常老的 NDK 头文件中可能没有声明/无法链接 dl_iterate_phdr 的情况；
// 通过这个包装函数调用可以避免产生硬性的链接期依赖。
int dl_iterate_phdr_wrapper(int (*__callback)(struct dl_phdr_info *, size_t,
                                              void *),
                            void *__data) {
  if (dl_iterate_phdr) {
    return dl_iterate_phdr(__callback, __data);
  }
  return 0;
}

int DlFcn::android_api_;

/**
 * Cache the running device's API level once, since dlopen/dlsym below need to
 * branch on it (pre-N, N/N_MR1, O+, Q+ all need different bypass strategies).
 *
 * 中文：只缓存一次当前设备的 API 级别，因为下面的 dlopen/dlsym 需要据此分支
 * 处理（N 之前、N/N_MR1、O 及以上、Q 及以上分别需要不同的绕过策略）。
 */
void DlFcn::init_api() {
  android_api_ = android_get_device_api_level();
  ALOGV("android_api_ = %d", android_api_);
}

static pthread_once_t once_control = PTHREAD_ONCE_INIT;

/**
 * dl_iterate_phdr callback used only on Android N/N_MR1: since those releases don't
 * expose __loader_dlopen, we instead walk the already-loaded library list looking
 * for one whose path contains the requested name, and capture its phdr/load address.
 *
 * 中文：仅在 Android N/N_MR1 上使用的 dl_iterate_phdr 回调：由于这些系统版本
 * 没有暴露 __loader_dlopen，我们改为遍历已加载的库列表，寻找路径中包含目标
 * 名称的那个，并记录下它的 phdr/加载地址。
 */
// Used for DlFcn::dlopen above android M
static int dl_iterate_callback(dl_phdr_info *info, size_t size, void *data) {
  ALOGV("dl_iterate_callback %s %p", info->dlpi_name, info->dlpi_addr);
  auto target = reinterpret_cast<DlFcn::dl_iterate_data *>(data);
  if (info->dlpi_addr != 0 &&
      strstr(info->dlpi_name, target->info_.dlpi_name)) {
    target->info_.dlpi_name = info->dlpi_name;
    target->info_.dlpi_addr = info->dlpi_addr;
    target->info_.dlpi_phdr = info->dlpi_phdr;
    target->info_.dlpi_phnum = info->dlpi_phnum;

    // break iterate
    return 1;
  }
  // continue iterate
  return 0;
}

using __loader_dlopen_fn = void *(*)(const char *filename, int flag,
                                     void *address);

/**
 * dlopen() replacement that works around Android's linker namespace restrictions,
 * which otherwise cause plain ::dlopen() to fail (return null) for libraries outside
 * the caller's allowed namespace (e.g. platform-internal libraries not on the NDK
 * allowlist). Strategy depends on API level:
 *  - < N: the restriction doesn't exist yet, so the system dlopen() works directly.
 *  - O+: fetch libdl.so's private __loader_dlopen symbol (bypassing the public,
 *    namespace-checked dlopen entry point) and call it directly; on Q+ where a
 *    caller-address-based namespace lookup can still fail, fall back to resolving
 *    the caller's load address via dl_iterate_phdr and retry with that as context.
 *  - N/N_MR1: no __loader_dlopen exists yet; instead we just record the matching
 *    dl_phdr_info from dl_iterate_phdr and hand back an opaque handle carrying it,
 *    to be parsed later ourselves in dlsym() below.
 *
 * 中文：绕开 Android 链接器命名空间限制的 dlopen() 替代实现；如果不这样做，普通
 * 的 ::dlopen() 对调用方命名空间之外的库（例如不在 NDK 白名单上的平台内部库）
 * 会直接失败（返回 null）。具体策略依 API 级别而定：
 *  - < N：此时限制还不存在，系统 dlopen() 可以直接工作。
 *  - O 及以上：取出 libdl.so 内部私有的 __loader_dlopen 符号（绕开会做命名空间
 *    检查的公开 dlopen 入口）并直接调用；在 Q 及以上，若基于调用方地址的
 *    命名空间查找仍然失败，则退而通过 dl_iterate_phdr 解析调用方的加载地址，
 *    并以此为上下文重试。
 *  - N/N_MR1：此时还没有 __loader_dlopen；我们只是记录下 dl_iterate_phdr 匹配到
 *    的 dl_phdr_info，并返回一个携带该信息的不透明句柄，留给下面的 dlsym() 自己
 *    解析。
 */
KWAI_EXPORT void *DlFcn::dlopen(const char *lib_name, int flags) {
  pthread_once(&once_control, init_api);
  if (android_api_ < __ANDROID_API_N__) {
    return ::dlopen(lib_name, flags);
  }
  if (android_api_ >= __ANDROID_API_O__) {
    void *handle = ::dlopen("libdl.so", RTLD_NOW);
    KCHECKP(handle)
    auto __loader_dlopen = reinterpret_cast<__loader_dlopen_fn>(
        ::dlsym(handle, "__loader_dlopen"));
    KCHECKP(__loader_dlopen)
    if (android_api_ < __ANDROID_API_Q__) {
      return __loader_dlopen(lib_name, flags, (void *)dlerror);
    } else {
      handle = __loader_dlopen(lib_name, flags, (void *)dlerror);
      if (handle == nullptr) {
        // Android Q added "runtime" namespace
        dl_iterate_data data{};
        data.info_.dlpi_name = lib_name;
        dl_iterate_phdr_wrapper(dl_iterate_callback, &data);
        KCHECKP(data.info_.dlpi_addr > 0)
        handle = __loader_dlopen(lib_name, flags, (void *)data.info_.dlpi_addr);
      }
      return handle;
    }
  }
  // __ANDROID_API_N__ && __ANDROID_API_N_MR1__
  auto *data = new dl_iterate_data();
  data->info_.dlpi_name = lib_name;
  dl_iterate_phdr_wrapper(dl_iterate_callback, data);

  return data;
}

/**
 * dlsym() counterpart to dlopen() above. On N/N_MR1, |handle| is not a real linker
 * handle but our own dl_iterate_data captured earlier, so we cannot call the system
 * ::dlsym() at all - instead we mmap/parse the target .so's ELF directly (ElfReader)
 * and resolve the symbol's address ourselves relative to its load address. On every
 * other API level the system dlsym() still works fine because dlopen() above returned
 * a real linker handle there.
 *
 * 中文：与上面 dlopen() 对应的 dlsym() 实现。在 N/N_MR1 上，|handle| 并不是一个
 * 真正的链接器句柄，而是之前捕获的我们自己的 dl_iterate_data，因此完全无法调用
 * 系统的 ::dlsym()——我们改为直接 mmap/解析目标 .so 的 ELF（ElfReader），并
 * 相对其加载地址自行解析出符号地址。在其他所有 API 级别上，由于上面的
 * dlopen() 返回的是真正的链接器句柄，系统 dlsym() 仍然可以正常工作。
 */
KWAI_EXPORT void *DlFcn::dlsym(void *handle, const char *name) {
  KCHECKP(handle)
  auto is_android_N = []() -> bool {
    return android_api_ == __ANDROID_API_N__ ||
           android_api_ == __ANDROID_API_N_MR1__;
  };

  if (!is_android_N()) {
    return ::dlsym(handle, name);
  }

  // __ANDROID_API_N__ && __ANDROID_API_N_MR1__
  auto *data = (dl_iterate_data *)handle;
  if (!data->info_.dlpi_name || data->info_.dlpi_name[0] != '/') {
    return nullptr;
  }

  ElfReader elf_reader(std::make_shared<FileElfWrapper>(data->info_.dlpi_name));
  if (!elf_reader.Init()) {
    return nullptr;
  }

  return elf_reader.LookupSymbol(name, data->info_.dlpi_addr, is_android_N());
}

/**
 * dlclose() counterpart: on N/N_MR1 there's no real linker handle to release, just
 * our heap-allocated dl_iterate_data captured in dlopen(); everywhere else defers
 * to the system ::dlclose() since a real linker handle was returned.
 *
 * 中文：与之对应的 dlclose() 实现：在 N/N_MR1 上没有真正的链接器句柄可释放，
 * 只有 dlopen() 中在堆上分配并捕获的 dl_iterate_data；其余情况下由于返回的是
 * 真正的链接器句柄，统一交给系统的 ::dlclose() 处理。
 */
KWAI_EXPORT int DlFcn::dlclose(void *handle) {
  if (android_api_ != __ANDROID_API_N__ &&
      android_api_ != __ANDROID_API_N_MR1__) {
    return ::dlclose(handle);
  }
  // __ANDROID_API_N__ && __ANDROID_API_N_MR1__
  delete (dl_iterate_data *)handle;
  return 0;
}

/**
 * Alternative to DlFcn::dlopen() that never calls into the system linker at all:
 * it locates the target library's load base by scanning /proc/self/maps (or
 * dl_iterate_phdr) via MapUtil, entirely independent of linker namespace rules.
 * This is the only way to reach symbols in .symtab (LOCAL/internal, not exported
 * via .dynsym) since the system dlsym() can only ever return .dynsym symbols.
 * Heavier than dlopen() above (mmaps/parses the whole ELF), so avoid using it in
 * low-memory or hot-path scenarios - see dlsym_elf below for amortizing the cost.
 *
 * 中文：DlFcn::dlopen() 的另一种实现，完全不调用系统链接器：通过 MapUtil 扫描
 * /proc/self/maps（或使用 dl_iterate_phdr）来定位目标库的加载基址，完全独立于
 * 链接器命名空间规则。由于系统 dlsym() 永远只能返回 .dynsym 中的符号，这是
 * 唯一能够获取 .symtab 中符号（LOCAL/内部符号，未通过 .dynsym 导出）的方式。
 * 相比上面的 dlopen()（要 mmap/解析整个 ELF）开销更大，因此应避免在低内存或
 * 热路径场景中使用——参见下面的 dlsym_elf，了解如何摊薄这部分开销。
 */
KWAI_EXPORT void *DlFcn::dlopen_elf(const char *lib_name, int flags) {
  pthread_once(&once_control, init_api);
  ElfW(Addr) load_base;
  std::string so_full_name;
  // Find where lib_name is actually mapped in this process's address space -
  // this is how we get a load base without asking the (namespace-restricted)
  // linker itself.
  // 中文：找出 lib_name 在当前进程地址空间中实际映射的位置——这就是我们在不
  // 询问（受命名空间限制的）链接器本身的情况下获取加载基址的方式。
  bool ret =
      MapUtil::GetLoadInfo(lib_name, &load_base, so_full_name, android_api_);

  if (!ret || so_full_name.empty() || so_full_name[0] != '/') {
    return nullptr;
  }

  SoDlInfo *so_dl_info = new (std::nothrow) SoDlInfo;
  if (!so_dl_info) {
    ALOGE("no memory for %s", so_full_name.c_str());
    return nullptr;
  }

  so_dl_info->load_base = load_base;
  so_dl_info->full_name = so_full_name;
  return so_dl_info;
}

/**
 * Resolve |name| against the library opened by dlopen_elf(), by re-parsing its ELF
 * sections (ElfReader) rather than any linker symbol table lookup. Callers fetching
 * multiple symbols from the same library should reuse one dlopen_elf() handle across
 * several dlsym_elf() calls rather than reopening/reparsing per symbol.
 *
 * 中文：针对 dlopen_elf() 打开的库解析 |name|，做法是重新解析其 ELF section
 * （ElfReader），而不是查询任何链接器符号表。如果调用方需要从同一个库中获取
 * 多个符号，应当复用同一个 dlopen_elf() 句柄，多次调用 dlsym_elf()，而不是
 * 每个符号都重新打开/重新解析一遍。
 */
KWAI_EXPORT void *DlFcn::dlsym_elf(void *handle, const char *name) {
  KCHECKP(handle)
  auto *so_dl_info = reinterpret_cast<SoDlInfo *>(handle);
  ElfReader elf_reader(
      std::make_shared<FileElfWrapper>(so_dl_info->full_name.c_str()));

  if (!elf_reader.Init()) {
    return nullptr;
  }

  return elf_reader.LookupSymbol(name, so_dl_info->load_base);
}

/**
 * Release the SoDlInfo allocated by dlopen_elf(); there's no linker handle to close
 * since this path never went through the system linker in the first place.
 *
 * 中文：释放 dlopen_elf() 分配的 SoDlInfo；由于这条路径压根没有经过系统链接器，
 * 也就没有链接器句柄需要关闭。
 */
KWAI_EXPORT int DlFcn::dlclose_elf(void *handle) {
  KCHECKI(handle)
  delete reinterpret_cast<SoDlInfo *>(handle);
  return 0;
}

}  // namespace linker

}  // namespace kwai