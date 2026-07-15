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

#include "hprof_dump_v_impl.h"

#include <dlfcn.h>

#include <kwai_linker/kwai_dlfcn.h>
#include <bionic/tls.h>
#include <log/kcheck.h>

#include <memory>

#include "defines.h"

#undef LOG_TAG
#define LOG_TAG "HprofDumpVImpl"

namespace kwai {
namespace leak_monitor {

using namespace kwai::linker;

/**
 * 获取 Android 15（V）及以上版本使用的单例实现。
 */
HprofDumpVImpl &HprofDumpVImpl::GetInstance() {
  static HprofDumpVImpl instance;
  return instance;
}

HprofDumpVImpl::HprofDumpVImpl()
    : HprofDumpImpl(),
      init_done_(false),
      ssa_constructor_fnc_(nullptr), ssa_destructor_fnc_(nullptr),
      sgc_constructor_fnc_(nullptr), sgc_destructor_fnc_(nullptr),
      thread_list_lock_ptr_(nullptr), exclusive_lock_fnc_(nullptr), exclusive_unlock_fnc_(nullptr),
      dump_heap_func_(nullptr),
      ssa_instance_(nullptr), sgc_instance_(nullptr) {}

/**
 * 解析 Android 15+（V）版本上所需的 ART 内部符号：ScopedSuspendAll /
 * ScopedGCCriticalSection 构造析构、thread_list_lock_ 锁指针及加解锁函数、
 * 以及 DumpHeap。
 *
 * 这里使用的是 dlopen_elf / dlsym_elf（而不是 below_r/below_v 实现里用的
 * 普通 dlopen/dlsym）：更高版本 Android 对系统库的 linker 命名空间隔离更严格，
 * 常规 dlopen("libart.so") 可能被限制或返回受限视图，dlopen_elf/dlsym_elf
 * 是 kwai_dlfcn 提供的、直接解析 ELF 文件本身来查找符号地址的实现，
 * 从而绕开 linker 命名空间对 dlopen/dlsym 的限制，稳定拿到 ART 内部符号。
 */
bool HprofDumpVImpl::Initialize() {
  if (init_done_) {
    return true;
  }

  std::unique_ptr<void, decltype(&DlFcn::dlclose_elf)>
      handle(DlFcn::dlopen_elf("libart.so", RTLD_NOW), DlFcn::dlclose_elf);
  KCHECKB(handle)

  // art::ScopedSuspendAll 构造/析构函数：挂起/恢复除当前线程外的所有 ART 线程。
  ssa_constructor_fnc_ = (void (*)(void *, const char *, bool))DlFcn::dlsym_elf(
      handle.get(), "_ZN3art16ScopedSuspendAllC1EPKcb");
  KCHECKB(ssa_constructor_fnc_)
  ssa_destructor_fnc_ = (void (*)(void *))DlFcn::dlsym_elf(
      handle.get(), "_ZN3art16ScopedSuspendAllD1Ev");
  KCHECKB(ssa_destructor_fnc_)

  // art::gc::ScopedGCCriticalSection 构造/析构函数：阻止 GC 在挂起/dump 期间运行。
  sgc_constructor_fnc_ = (void (*)(void *, void *, GcCause, CollectorType))DlFcn::dlsym_elf(
      handle.get(),
      "_ZN3art2gc23ScopedGCCriticalSectionC1EPNS_6ThreadENS0_7GcCauseENS0_13CollectorTypeE");
  KCHECKB(sgc_constructor_fnc_)
  sgc_destructor_fnc_ =
      (void (*)(void *))DlFcn::dlsym_elf(handle.get(), "_ZN3art2gc23ScopedGCCriticalSectionD1Ev");
  KCHECKB(sgc_destructor_fnc_)

  // art::Locks::thread_list_lock_：ART 用于保护线程列表的全局锁。
  // 在 Android 15+ 上，fork() 调用需要在持有这把锁的情况下进行
  // （见下方 Fork() 的实现与其注释），而不是像旧版本那样在 fork 前
  // 释放 mutator 锁，这是本实现相较于 HprofDumpBelowVImpl 的关键差异。
  thread_list_lock_ptr_ =
      (void **)DlFcn::dlsym_elf(handle.get(), "_ZN3art5Locks17thread_list_lock_E");
  KCHECKB(thread_list_lock_ptr_)
  // art::Mutex::ExclusiveLock(Thread*)：对 thread_list_lock_ 这类互斥锁加锁。
  exclusive_lock_fnc_ = (void (*)(void *, void *))DlFcn::dlsym_elf(
      handle.get(), "_ZN3art5Mutex13ExclusiveLockEPNS_6ThreadE");
  KCHECKB(exclusive_lock_fnc_)
  // art::Mutex::ExclusiveUnlock(Thread*)：与上面配对的解锁函数。
  exclusive_unlock_fnc_ = (void (*)(void *, void *))DlFcn::dlsym_elf(
      handle.get(), "_ZN3art5Mutex15ExclusiveUnlockEPNS_6ThreadE");
  KCHECKB(exclusive_unlock_fnc_)

  // art::hprof::DumpHeap()，真正把堆内容写成 hprof 文件的 ART 内部函数。
  dump_heap_func_ =
      (void (*)(const char *, int, bool))DlFcn::dlsym_elf(handle.get(), "_ZN3art5hprof8DumpHeapEPKcib");
  KCHECKB(dump_heap_func_)

  init_done_ = true;
  return true;
}

// class ScopedSuspendAll : public ValueObject {
// };
//
// class ValueObject {
// };
/**
 * 本地“影子类”，其内存布局刻意对齐 ART 内部 art::ScopedSuspendAll 的大小，
 * 但构造/析构逻辑并不在这里实现，而是转发给 dlsym 解析出来的 ART 内部
 * 构造/析构函数指针执行。这样可以用标准 C++ RAII（构造即挂起、析构即恢复）
 * 的写法来管理“挂起所有线程”这个操作的生命周期，同时不需要依赖 ART 内部
 * 类的真实定义（该定义未公开导出）。
 */
class ScopedSuspendAll {
 public:
  // 构造函数即触发 art::ScopedSuspendAll 的构造逻辑：
  // 挂起除当前线程外的所有 ART Java 线程。
  ScopedSuspendAll(const char *cause, bool long_suspend) {
    HprofDumpVImpl::GetInstance().ssa_constructor_fnc_(this, cause, long_suspend);
  }

  // 析构函数触发 art::ScopedSuspendAll 的析构逻辑：恢复被挂起的线程。
  ~ScopedSuspendAll() {
    HprofDumpVImpl::GetInstance().ssa_destructor_fnc_(this);
  }

 private:
  // Over size for device compatibility
  [[maybe_unused]] char placeholder_[64] = {0};
};

// class GCCriticalSection {
//  private:
//   Thread* const self_;
//   const char* section_name_;
// };
//
// class ScopedGCCriticalSection {
//  private:
//   GCCriticalSection critical_section_;
//   const char* old_no_suspend_reason_;
// };
/**
 * 同上，是 ART 内部 art::gc::ScopedGCCriticalSection 的本地影子类，
 * 用 RAII 管理“GC 临界区”的生命周期：构造时阻止 GC 运行，
 * 析构时恢复，防止在挂起线程、fork、dump 期间发生 GC 移动/回收对象
 * 导致堆快照不一致。
 */
class ScopedGCCriticalSection {
 public:
  ScopedGCCriticalSection(void *self, GcCause cause, CollectorType collector_type) {
    HprofDumpVImpl::GetInstance().sgc_constructor_fnc_(this, self, cause, collector_type);
  }

  ~ScopedGCCriticalSection() {
    HprofDumpVImpl::GetInstance().sgc_destructor_fnc_(this);
  }

 private:
  // Over size for device compatibility
  [[maybe_unused]] char placeholder_[64] = {0};
};

/**
 * 通用的 RAII 互斥锁封装，转发给 dlsym 解析出的 art::Mutex 加解锁函数。
 * 这里专门用来在 fork() 期间持有 art::Locks::thread_list_lock_：
 * Android 15+ 上 ART 要求 fork 调用发生在持有该锁的状态下（对齐 AOSP
 * perfetto_hprof 的做法），构造时加锁、析构时解锁，保证无论 Fork()
 * 正常返回还是提前 return，锁都会被正确释放。
 */
class MutexLock {
 public:
  MutexLock(void *self, void **mu_ptr) : self_(self), mu_ptr_(mu_ptr) {
    HprofDumpVImpl::GetInstance().exclusive_lock_fnc_(*mu_ptr_, self_);
  }

  ~MutexLock() {
    HprofDumpVImpl::GetInstance().exclusive_unlock_fnc_(*mu_ptr_, self_);
  }

 private:
  void *self_;
  void **mu_ptr_;
};

/**
 * 挂起除当前线程外的所有 ART 线程，为随后的 fork() 做准备。
 * 与 HprofDumpBelowVImpl::Suspend 不同，这里不再显式释放 mutator 锁——
 * Android 15+ 上避免子进程死锁的手段改为在 Fork() 里持有
 * thread_list_lock_（见 Fork() 注释），两个版本分别对齐了各自 AOSP
 * 版本里 ART/perfetto_hprof 的实际处理方式。
 */
bool HprofDumpVImpl::Suspend() {
  KCHECKB(init_done_)

  // see
  // perfetto ForkAndRun: https://cs.android.com/android/platform/superproject/main/+/main:art/perfetto_hprof/perfetto_hprof.cc;l=985;
  // hprof DumpHeap: https://cs.android.com/android/platform/superproject/main/+/main:art/runtime/hprof/hprof.cc;l=1616
  // __get_tls()[TLS_SLOT_ART_THREAD_SELF]：从当前线程的 TLS 槽位取出
  // art::Thread* self 指针，后续调用 ART 内部 API 都需要用它标识调用线程。
  void *self = __get_tls()[TLS_SLOT_ART_THREAD_SELF];
  // 先进入 GC 临界区阻止 GC 运行，再挂起所有线程；顺序与 below-V 实现一致，
  // 都是为了避免挂起期间发生 GC 导致堆快照不一致。
  sgc_instance_ = std::make_unique<ScopedGCCriticalSection>(self, kGcCauseHprof, kCollectorTypeHprof);
  ssa_instance_ = std::make_unique<ScopedSuspendAll>(LOG_TAG, true);

  return true;
}

/**
 * 覆写基类 Fork()：在真正调用 fork() 之前，先持有 ART 的
 * thread_list_lock_。这是 Android 15+ 上 ART 实现变化后要求的做法——
 * fork 时必须持有该锁，否则子进程里可能出现线程列表状态不一致的问题；
 * MutexLock 是一个 RAII 包装，离开作用域（return 之后）自动解锁，
 * 因此这把锁只在 fork() 调用这一瞬间被短暂持有。
 */
pid_t HprofDumpVImpl::Fork() {
  KCHECKI(init_done_)

  // see https://cs.android.com/android/_/android/platform/art/+/5656cd41481ab03eb6df3aec7eda296ebbef667b
  void *self = __get_tls()[TLS_SLOT_ART_THREAD_SELF];
  MutexLock lk(self, thread_list_lock_ptr_);
  return HprofDumpImpl::Fork();
}

/**
 * 恢复父进程中的所有 ART 线程：依次析构 ScopedSuspendAll /
 * ScopedGCCriticalSection（顺序与构造相反），使线程恢复运行、GC 临界区解除。
 */
bool HprofDumpVImpl::Resume() {
  KCHECKB(init_done_)

  ssa_instance_.reset();
  sgc_instance_.reset();

  return true;
}

/**
 * 调用 art::hprof::DumpHeap 把当前进程（应为 fork 出的子进程）的堆快照
 * 写入 hprof 文件。
 *
 * 注意这里在 dump 之前先调用了 Resume()：这是本实现（相较于其他两个
 * 版本）的特殊之处——Android 15+ 上子进程内如果继续保持“挂起状态”对应的
 * 内部数据结构不去恢复，DumpHeap 内部逻辑会出现不兼容问题，因此约定
 * 子进程必须先 Resume（对子进程自身的状态而言，不影响父进程，
 * 父子进程内存已经因 fork 而各自独立）再执行真正的 dump。
 */
void HprofDumpVImpl::DumpHeap(const char* filename) {
  KCHECKV(init_done_)

  Resume();
  // If "direct_to_ddms" is true, the other arguments are ignored, and data is
  // sent directly to DDMS.
  // If "fd" is >= 0, the output will be written to that file descriptor.
  // Otherwise, "filename" is used to create an output file.
  // DumpHeap(const char* filename, int fd, bool direct_to_ddms)
  dump_heap_func_(filename, -1, false);
}

} // namespace leak_monitor
} // namespace kwai
