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

#include "hprof_dump_impl.h"

#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <cerrno>

#include <log/kcheck.h>

#include "defines.h"

#include "hprof_dump.h"
#include "hprof_dump_below_r_impl.h"
#include "hprof_dump_below_v_impl.h"
#include "hprof_dump_v_impl.h"

#undef LOG_TAG
#define LOG_TAG "HprofDumpImpl"

namespace kwai {
namespace leak_monitor {

/**
 * 根据设备 Android API Level 挑选具体的挂起/fork/dump 实现类。
 * 不同大版本的 ART 对外暴露的挂起 VM 方式、可 dlsym 到的内部符号都不一样，
 * 因此需要在运行时按版本分派到 R 以下 / R~V 之间 / V 及以上 三套实现。
 */
HprofDumpImpl &HprofDumpImpl::GetInstance(int android_api) {
  if (android_api < __ANDROID_API_R__) {
    return HprofDumpBelowRImpl::GetInstance();
  } else if (android_api < __ANDROID_API_V__) {
    return HprofDumpBelowVImpl::GetInstance();
  } else {
    // hprof_constructor_fnc_ symbol not exists on Android 14
    return HprofDumpVImpl::GetInstance();
  }
}

/**
 * 对 fork() 的默认封装，供各版本实现在需要时覆写（例如 V 版实现需要在
 * fork 前后额外持有 ART 内部锁，见 HprofDumpVImpl::Fork）。
 */
pid_t HprofDumpImpl::Fork() {
  // fork()：复制当前进程创建子进程，父子进程的内存页以 Copy-on-Write 方式共享，
  // 因此复制开销与堆大小无关、几乎是常数时间；子进程后续对内存的读取
  // 看到的是 fork 那一刻的完整快照，不受父进程后续写操作影响，
  // 这正是本模块能在“不阻塞父进程太久”的前提下拿到一致堆快照的关键机制。
  return fork();
}

/**
 * “挂起 -> fork”流程的统一入口：先挂起 ART 的所有 Java 线程，
 * 再 fork 出子进程，并只在子进程分支里做子进程专属的收尾设置。
 * 之所以要先挂起再 fork，是因为多线程进程 fork 后子进程只会保留
 * 发起 fork 调用的那一个线程，其余线程及其可能持有的锁在子进程里
 * 永远不会被释放（那些线程根本不存在了），必须先把 Java 线程都挂起、
 * 相关锁释放掉，才能避免子进程内的死锁。
 */
pid_t HprofDumpImpl::SuspendAndFork() {
  if (!Suspend()) {
    return -1;
  }

  pid_t pid = Fork();
  if (pid == 0) {
    // Set timeout for child process
    // alarm(60)：为子进程设置 60 秒超时闹钟，一旦 dump 逻辑异常挂住，
    // 超时后内核会向子进程投递 SIGALRM（默认处理动作是终止进程），
    // 防止子进程无限占用内存/句柄而不退出。
    alarm(60);
    // prctl(PR_SET_NAME, ...)：修改子进程的线程/进程名，
    // 方便在 ps、/proc/<pid>/comm 等工具中一眼识别出这是 fork 出来的 dump 进程，
    // 便于线上定位和排查异常子进程。
    prctl(PR_SET_NAME, "forked-dump-process");
  }
  return pid;
}

/**
 * 恢复父进程线程运行，并阻塞等待子进程退出。
 * 之所以需要 waitpid，一是避免子进程退出后变成僵尸进程得不到回收，
 * 二是保证方法返回时子进程已经真正结束、hprof 文件已经完整写完，
 * 调用方可以放心地去读取/上传这个文件。
 */
bool HprofDumpImpl::ResumeAndWait(pid_t pid) {
  if (!Resume()) {
    return false;
  }

  int status;
  for (;;) {
    // waitpid()：阻塞等待指定 pid 的子进程退出并回收其内核资源（避免僵尸进程），
    // 同时充当同步点——函数返回时即可确认子进程（及其写文件操作）已经结束。
    if (waitpid(pid, &status, 0) != -1) {
      if (!WIFEXITED(status)) {
        ALOGE("Child process %d exited with status %d, terminated by signal %d",
              pid, WEXITSTATUS(status), WTERMSIG(status));
        return false;
      }
      return true;
    }
    // 被信号中断调用的话，再发起一次waitpid调用即可
    if (errno == EINTR){
      continue;
    }
    return false;
  }
}

} // namespace leak_monitor
} // namespace kwai
