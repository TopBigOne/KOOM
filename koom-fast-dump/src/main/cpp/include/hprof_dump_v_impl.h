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

#ifndef KOOM_HPROF_DUMP_V_IMPL_H_
#define KOOM_HPROF_DUMP_V_IMPL_H_

#include "hprof_dump_impl.h"

#include <memory>

#include "defines.h"

namespace kwai {
namespace leak_monitor {

class ScopedSuspendAll;
class ScopedGCCriticalSection;
class MutexLock;

/**
 * HprofDumpImpl for Android 15 - Android 16 (Baklava)
 *
 * use art::ScopedSuspendAll::ScopedSuspendAll to Suspend & Resume,
 * use art::hprof::DumpHeap to DumpHeap, **Resume before DumpHeap**
 */
class HprofDumpVImpl : public HprofDumpImpl {
 public:
  // 获取本版本实现的单例。
  static HprofDumpVImpl &GetInstance();

 public:
  HprofDumpVImpl();
  ~HprofDumpVImpl() override = default;

 public:
  // dlopen_elf/dlsym_elf 解析 ScopedSuspendAll/ScopedGCCriticalSection/
  // thread_list_lock_ 加解锁/DumpHeap 等符号（Android 15+ 上普通
  // dlopen/dlsym 可能受 linker 命名空间限制，需要直接解析 ELF）。
  bool Initialize() override;

 public:
  // 挂起除当前线程外的所有 ART 线程（不释放锁，见 .cpp 中的说明）。
  bool Suspend() override;
  // 覆写基类 Fork()：在持有 thread_list_lock_ 的情况下调用 fork()，
  // 这是本版本避免子进程状态不一致/死锁所采用的方式。
  pid_t Fork() override;
  // 恢复被挂起的线程。
  bool Resume() override;

  // 调用 art::hprof::DumpHeap() 写出 hprof 快照文件；
  // 注意实现中会先 Resume() 再 dump，见 .cpp 中的说明。
  void DumpHeap(const char* filename) override;

 private:
  bool init_done_;

 private:
  // art::ScopedSuspendAll::ScopedSuspendAll()
  void (*ssa_constructor_fnc_)(void *handle, const char *cause, bool long_suspend);
  // art::ScopedSuspendAll::~ScopedSuspendAll()
  void (*ssa_destructor_fnc_)(void *handle);
  // art::gc::ScopedGCCriticalSection::ScopedGCCriticalSection()
  void (*sgc_constructor_fnc_)(void *handle, void *self, GcCause cause, CollectorType collector_type);
  // art::gc::ScopedGCCriticalSection::~ScopedGCCriticalSection()
  void (*sgc_destructor_fnc_)(void *handle);

  // art::Locks::thread_list_lock_
  void **thread_list_lock_ptr_;
  // art::Mutex::ExclusiveLock(art::Thread*)
  void (*exclusive_lock_fnc_)(void *, void *self);
  // art::Mutex::ExclusiveUnlock(art::Thread*)
  void (*exclusive_unlock_fnc_)(void *, void *self);

  // art::hprof::DumpHeap(char const*, int, bool)
  void (*dump_heap_func_)(const char *filename, int, bool);

 private:
  std::unique_ptr<ScopedSuspendAll> ssa_instance_;
  std::unique_ptr<ScopedGCCriticalSection> sgc_instance_;

 private:
  friend class ScopedSuspendAll;
  friend class ScopedGCCriticalSection;
  friend class MutexLock;
};

} // namespace leak_monitor
} // namespace kwai

#endif //KOOM_HPROF_DUMP_V_IMPL_H_
