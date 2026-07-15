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

#ifndef KOOM_HPROF_DUMP_IMPL_H_
#define KOOM_HPROF_DUMP_IMPL_H_

#include <sys/types.h>

namespace kwai {
namespace leak_monitor {

/**
 * “挂起 ART VM -> fork -> 恢复/dump”流程的抽象基类。
 * 不同 Android 版本挂起 VM、加解锁的具体 ART 内部符号不同，
 * 因此把版本相关的部分（Initialize/Suspend/Fork/Resume/DumpHeap）声明为
 * 虚函数，由 HprofDumpBelowRImpl / HprofDumpBelowVImpl / HprofDumpVImpl
 * 分别实现，公共的调度逻辑（SuspendAndFork/ResumeAndWait）在基类里实现一次。
 */
class HprofDumpImpl {
 public:
  // 根据设备 Android API Level 返回对应版本的具体实现单例。
  static HprofDumpImpl &GetInstance(int android_api);

 public:
  virtual ~HprofDumpImpl() {};

 public:
  // 一次性初始化：dlopen 目标 so 并 dlsym 解析出后续所需的 ART 内部符号。
  virtual bool Initialize() = 0;

 public:
  // 挂起除当前线程外的所有 ART Java 线程，为 fork 做准备。
  virtual bool Suspend() = 0;
  // 执行真正的 fork() 系统调用，默认实现直接调用 fork()；
  // 部分版本（见 HprofDumpVImpl）需要在 fork 前后额外持有 ART 内部锁，因此声明为虚函数。
  virtual pid_t Fork();
  // 恢复此前被挂起的所有线程。
  virtual bool Resume() = 0;

  // 在当前进程（应为 fork 出的子进程）写出 hprof 堆快照文件。
  virtual void DumpHeap(const char* filename) = 0;

 public:
  // Avoid Any Not Necessary actions on the forked process
  // 组合 Suspend() + Fork()：先挂起所有 Java 线程再 fork，
  // 避免多线程进程 fork 后子进程中只剩当前线程、其他线程持有的锁无法释放而死锁。
  pid_t SuspendAndFork();
  // 组合 Resume() + waitpid()：恢复父进程线程运行的同时，
  // 阻塞等待子进程退出，确保 hprof 文件已完整写入。
  bool ResumeAndWait(pid_t pid);
};

} // namespace leak_monitor
} // namespace kwai

#endif //KOOM_HPROF_DUMP_IMPL_H_
