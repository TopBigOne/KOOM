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
 * Created by Qiushi Xue <xueqiushi@kuaishou.com> on 2021.
 *
 */

#ifndef KOOM_HPROF_DUMP_H
#define KOOM_HPROF_DUMP_H

#include <android-base/macros.h>

#include <memory>
#include <string>

namespace kwai {
namespace leak_monitor {

/**
 * fork 出的子进程专用的退出方式：必须调用 _exit() 而不是 exit()。
 * exit() 会执行 C/C++ 运行时的清理流程（全局对象析构、atexit 注册的回调等），
 * 但子进程只是父进程状态在 fork 那一刻的部分拷贝（例如只保留了一个线程），
 * 在这种不完整状态下运行清理逻辑可能访问到不一致的全局状态从而崩溃；
 * _exit() 跳过这些清理，直接进入内核终止进程，是 fork 出的子进程唯一安全的退出方式。
 */
inline void FastExit(int exit_code) {
  _exit(exit_code);
}

class HprofDumpImpl;

/**
 * hprof dump 功能对外的统一门面（Facade），屏蔽掉不同 Android 版本
 * 挂起 ART VM / fork / dump 方式的差异，内部转发给按设备 API Level
 * 选出的具体 HprofDumpImpl 实现。
 */
class HprofDump {
 public:
  // 获取进程内唯一的 HprofDump 实例。
  static HprofDump &GetInstance();

  // 提前完成 dlopen/dlsym 等一次性初始化工作。
  void Initialize();

  // Avoid Any Not Necessary actions on the forked process
  // 挂起 ART 虚拟机所有 Java 线程后立即 fork()：
  // 返回值语义与系统调用 fork() 一致（0=子进程，>0=父进程且值为子进程 pid，<0=失败）。
  pid_t SuspendAndFork();
  // 父进程恢复被挂起的线程，不等待子进程。
  bool Resume();
  // 父进程恢复被挂起的线程，并阻塞等待子进程退出（即 hprof 文件已写完）。
  bool ResumeAndWait(pid_t pid);

  // 在当前进程（应为 fork 出的子进程）写出 hprof 堆快照文件。
  void DumpHeap(const char* filename);

 private:
  HprofDump();
  ~HprofDump() = default;
  DISALLOW_COPY_AND_ASSIGN(HprofDump);

 private:
  HprofDumpImpl &impl_;
};

}  // namespace leak_monitor
}  // namespace kwai

#endif  // KOOM_HPROF_DUMP_H
