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

#include "hprof_dump_below_v_impl.h"

#include <wait.h>
#include <dlfcn.h>
#include <csetjmp>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <memory>

#include <kwai_linker/kwai_dlfcn.h>
#include <bionic/tls.h>
#include <log/kcheck.h>

#include "defines.h"

#undef LOG_TAG
#define LOG_TAG "HprofDumpBelowVImpl"

namespace kwai {
namespace leak_monitor {

using namespace kwai::linker;

/**
 * 获取 Android 11 ~ 14（R ~ 未到 V）版本使用的单例实现。
 */
HprofDumpBelowVImpl &HprofDumpBelowVImpl::GetInstance() {
  static HprofDumpBelowVImpl instance;
  return instance;
}

HprofDumpBelowVImpl::HprofDumpBelowVImpl()
    : HprofDumpImpl(),
      init_done_(false),
      ssa_constructor_fnc_(nullptr), ssa_destructor_fnc_(nullptr),
      sgc_constructor_fnc_(nullptr), sgc_destructor_fnc_(nullptr),
      mutator_lock_ptr_(nullptr), exclusive_lock_fnc_(nullptr), exclusive_unlock_fnc_(nullptr),
      dump_heap_func_(nullptr),
      ssa_instance_(nullptr), sgc_instance_(nullptr) {}

/**
 * dlopen libart.so 并 dlsym 解析出 ScopedSuspendAll / ScopedGCCriticalSection
 * 的构造/析构函数、mutator_lock_ 锁指针及其加解锁函数、以及 DumpHeap 函数。
 * 这些都是 ART 运行时内部（非 NDK 导出）符号，Android 的 linker 命名空间
 * 限制了应用直接 dlopen/dlsym 系统库的内部实现，这里通过 kwai_dlfcn
 * 提供的 dlopen/dlsym 包装绕开该限制，在运行时按 C++ mangled 符号名查找。
 */
bool HprofDumpBelowVImpl::Initialize() {
  if (init_done_) {
    return true;
  }

  std::unique_ptr<void, decltype(&DlFcn::dlclose)>
      handle(DlFcn::dlopen("libart.so", RTLD_NOW), DlFcn::dlclose);
  KCHECKB(handle)

  // Over size for device compatibility
  // 这里只是分配一段原始内存作为 ART 内部对象（ScopedSuspendAll /
  // ScopedGCCriticalSection）的“placement 存储空间”，用固定大小的
  // char[64] 顶替真实类型，避免直接依赖 ART 内部类的完整定义（不同
  // 系统版本该类的实际大小可能不同，64 字节留有余量保证够用）。
  ssa_instance_ = std::make_unique<char[]>(64);
  sgc_instance_ = std::make_unique<char[]>(64);

  // art::ScopedSuspendAll::ScopedSuspendAll(const char*, bool) 构造函数，
  // 用于挂起除当前线程外的所有 ART 线程。
  ssa_constructor_fnc_ = (void (*)(void *, const char *, bool))DlFcn::dlsym(
      handle.get(), "_ZN3art16ScopedSuspendAllC1EPKcb");
  KCHECKB(ssa_constructor_fnc_)
  // art::ScopedSuspendAll 的析构函数，负责恢复被挂起的线程。
  ssa_destructor_fnc_ =
      (void (*)(void *))DlFcn::dlsym(handle.get(), "_ZN3art16ScopedSuspendAllD1Ev");
  KCHECKB(ssa_destructor_fnc_)

  // art::gc::ScopedGCCriticalSection 构造函数：阻止 GC 在挂起/dump 期间运行，
  // 避免 GC 移动/回收对象导致堆快照不一致。
  sgc_constructor_fnc_ = (void (*)(void *, void *, GcCause, CollectorType))DlFcn::dlsym(
      handle.get(),
      "_ZN3art2gc23ScopedGCCriticalSectionC1EPNS_6ThreadENS0_7GcCauseENS0_13CollectorTypeE");
  KCHECKB(sgc_constructor_fnc_)
  sgc_destructor_fnc_ =
      (void (*)(void *))DlFcn::dlsym(handle.get(), "_ZN3art2gc23ScopedGCCriticalSectionD1Ev");
  KCHECKB(sgc_destructor_fnc_)

  // art::Locks::mutator_lock_：ART 全局的 mutator 读写锁指针，
  // Suspend 时需要显式释放该锁，否则 fork 之后子进程里只剩当前线程，
  // 若锁恰好被其他（在子进程里已经消失的）线程持有，会导致子进程死锁。
  mutator_lock_ptr_ =
      (void **)DlFcn::dlsym(handle.get(), "_ZN3art5Locks13mutator_lock_E");
  KCHECKB(mutator_lock_ptr_)
  // art::ReaderWriterMutex::ExclusiveLock，用于 Resume 时重新加回 mutator 锁。
  exclusive_lock_fnc_ =(void (*)(void *, void *))DlFcn::dlsym(
      handle.get(), "_ZN3art17ReaderWriterMutex13ExclusiveLockEPNS_6ThreadE");
  KCHECKB(exclusive_lock_fnc_)
  // art::ReaderWriterMutex::ExclusiveUnlock，用于 Suspend 时提前释放 mutator 锁。
  exclusive_unlock_fnc_ = (void (*)(void *, void *))DlFcn::dlsym(
      handle.get(), "_ZN3art17ReaderWriterMutex15ExclusiveUnlockEPNS_6ThreadE");
  KCHECKB(exclusive_unlock_fnc_)

  // art::hprof::DumpHeap()，真正把堆内容写成 hprof 文件的 ART 内部函数。
  dump_heap_func_ =
      (void (*)(const char *, int, bool))DlFcn::dlsym(handle.get(), "_ZN3art5hprof8DumpHeapEPKcib");
  KCHECKB(dump_heap_func_)

  init_done_ = true;
  return true;
}

/**
 * 挂起除当前线程外的所有 ART 线程，并释放 mutator 锁，为随后的 fork() 做准备。
 * 释放 mutator 锁是本函数的关键：fork 之后子进程只保留发起调用的这一个线程，
 * 如果 mutator 锁此刻恰好被别的线程持有，那把锁在子进程里将永远等不到
 * 持有者线程去释放，从而造成子进程内的永久死锁；因此必须在 fork 之前
 * 显式把锁释放掉。
 */
bool HprofDumpBelowVImpl::Suspend() {
  KCHECKB(init_done_)

  // __get_tls()[TLS_SLOT_ART_THREAD_SELF]：读取当前线程的线程本地存储（TLS）槽位，
  // 取出 bionic/ART 为当前线程维护的 art::Thread* self 指针，
  // 后续所有 ART 内部加解锁 API 都需要传入这个 self 指针标识调用者线程。
  void *self = __get_tls()[TLS_SLOT_ART_THREAD_SELF];
  // 构造 ScopedGCCriticalSection：暂时阻止 GC 运行，防止挂起期间对象被移动/回收
  // 导致堆快照不一致。
  sgc_constructor_fnc_((void *)sgc_instance_.get(), self, kGcCauseHprof, kCollectorTypeHprof);
  // 构造 ScopedSuspendAll：真正挂起除当前线程外的所有 ART Java 线程。
  ssa_constructor_fnc_((void *)ssa_instance_.get(), LOG_TAG, true);
  // avoid deadlock with child process
  // exclusive_unlock_fnc_：显式释放 mutator_lock_，见函数头注释——
  // 这是避免 fork 后子进程死锁的关键一步。
  exclusive_unlock_fnc_(*mutator_lock_ptr_, self);
  // 提前析构 GC 临界区：GC 临界区只需要保证挂起线程那一刻不发生 GC 即可，
  // 没必要一直持有到 Resume，尽量缩小其生命周期。
  sgc_destructor_fnc_((void *)sgc_instance_.get());

  return true;
}

/**
 * 恢复父进程中的所有 ART 线程：先重新持有 mutator 锁（对应 Suspend 里的释放），
 * 再析构 ScopedSuspendAll 使所有线程真正被唤醒继续运行。
 */
bool HprofDumpBelowVImpl::Resume() {
  KCHECKB(init_done_)

  void *self = __get_tls()[TLS_SLOT_ART_THREAD_SELF];
  // exclusive_lock_fnc_：把 Suspend 阶段释放掉的 mutator_lock_ 重新加回来，
  // 恢复到挂起之前的锁状态，保证后续 Java 线程运行时锁语义正确。
  exclusive_lock_fnc_(*mutator_lock_ptr_, self);
  ssa_destructor_fnc_((void *)ssa_instance_.get());

  return true;
}

/**
 * 调用 art::hprof::DumpHeap 把当前进程（应为 fork 出的子进程）的堆快照
 * 写入 hprof 文件，供后续离线分析。
 */
void HprofDumpBelowVImpl::DumpHeap(const char* filename) {
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
