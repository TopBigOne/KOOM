/*
 * Copyright (c) 2025. Kwai, Inc. All rights reserved.
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
 * Created by wangzefeng <wangzefeng@kuaishou.com> on 2025.
 *
 */

#include "hprof_dump_below_r_impl.h"
#include "defines.h"

#include <dlfcn.h>
#include <kwai_linker/kwai_dlfcn.h>
#include <log/kcheck.h>

#undef LOG_TAG
#define LOG_TAG "HprofDumpBelowRImpl"

namespace kwai {
namespace leak_monitor {

using namespace kwai::linker;

/**
 * 获取 Android R 以下版本使用的单例实现。
 */
HprofDumpBelowRImpl &HprofDumpBelowRImpl::GetInstance() {
  static HprofDumpBelowRImpl instance;
  return instance;
}

HprofDumpBelowRImpl::HprofDumpBelowRImpl()
  : HprofDumpImpl(),
    init_done_(false),
    suspend_vm_fnc_(nullptr), resume_vm_fnc_(nullptr),
    dump_heap_func_(nullptr) {}

/**
 * 通过 dlopen/dlsym 解析出 art::Dbg::SuspendVM / art::Dbg::ResumeVM /
 * art::hprof::DumpHeap 这三个 ART 内部（未导出为 NDK 稳定符号）的函数地址。
 * 之所以要用 dlopen + 手写的 C++ mangled 符号名而不是直接调用，是因为
 * Android 从 N 开始对 libart.so 等系统库施加了 linker 命名空间限制，
 * 应用侧无法通过常规的头文件+动态链接直接使用这些内部符号，
 * 这里借助 kwai_dlfcn 绕开该限制，在运行时从 libart.so 中查表拿到函数指针。
 */
bool HprofDumpBelowRImpl::Initialize() {
  if (init_done_) {
    return true;
  }

  std::unique_ptr<void, decltype(&DlFcn::dlclose)>
      handle(DlFcn::dlopen("libart.so", RTLD_NOW), DlFcn::dlclose);
  KCHECKB(handle)

  // _ZN3art3Dbg9SuspendVMEv 是 art::Dbg::SuspendVM() 的 C++ mangled 名，
  // 该符号未被 NDK 导出，只能通过 dlsym 按名字动态查找。
  suspend_vm_fnc_ =
      (void (*)())DlFcn::dlsym(handle.get(), "_ZN3art3Dbg9SuspendVMEv");
  KCHECKB(suspend_vm_fnc_)
  // art::Dbg::ResumeVM()，与上面的 SuspendVM 配对使用。
  resume_vm_fnc_ =
      (void (*)())DlFcn::dlsym(handle.get(), "_ZN3art3Dbg8ResumeVMEv");
  KCHECKB(resume_vm_fnc_)

  // art::hprof::DumpHeap()，真正把堆内容写成 hprof 文件的 ART 内部函数。
  dump_heap_func_ =
      (void (*)(const char *, int, bool))DlFcn::dlsym(handle.get(), "_ZN3art5hprof8DumpHeapEPKcib");
  KCHECKB(dump_heap_func_)

  init_done_ = true;
  return true;
}

/**
 * 挂起所有 ART Java 线程（Android 5~10 上通过 art::Dbg::SuspendVM 实现）。
 * fork() 之前必须先让所有线程停在安全点，否则 fork 出的子进程里
 * 那些“凭空消失”的线程原本持有的锁将永远无法释放。
 */
bool HprofDumpBelowRImpl::Suspend() {
  KCHECKB(init_done_)
  suspend_vm_fnc_();
  return true;
}

/**
 * 恢复此前被挂起的所有 ART Java 线程，让父进程尽快继续正常运行。
 */
bool HprofDumpBelowRImpl::Resume() {
  KCHECKB(init_done_)
  resume_vm_fnc_();
  return true;
}

/**
 * 调用 art::hprof::DumpHeap 把当前进程（应为 fork 出的子进程）的堆快照
 * 写入 hprof 文件，供后续离线分析。
 */
void HprofDumpBelowRImpl::DumpHeap(const char* filename) {
  KCHECKV(init_done_)
  // If "direct_to_ddms" is true, the other arguments are ignored, and data is
  // sent directly to DDMS.
  // If "fd" is >= 0, the output will be written to that file descriptor.
  // Otherwise, "filename" is used to create an output file.
  // DumpHeap(const char* filename, int fd, bool direct_to_ddms)
  dump_heap_func_(filename, -1, false);
}

} // namespace leak_monitor
} // namespace kwai
