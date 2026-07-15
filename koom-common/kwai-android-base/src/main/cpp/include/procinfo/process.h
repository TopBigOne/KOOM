/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <type_traits>

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/unique_fd.h>

namespace android {
namespace procinfo {

#if defined(__linux__)

// Mirrors the single-character state codes the kernel writes into the
// "State:" field of /proc/<pid>/status (R/S/D/T/Z, see parse_state() in process.cpp).
// 中文：对应内核写入 /proc/<pid>/status 的 "State:" 字段中的单字符状态码
// （R/S/D/T/Z，参见 process.cpp 中的 parse_state()）。
enum ProcessState {
  kProcessStateUnknown,
  kProcessStateRunning,
  kProcessStateSleeping,
  kProcessStateUninterruptibleWait,
  kProcessStateStopped,
  kProcessStateZombie,
};

struct ProcessInfo {
  std::string name;
  ProcessState state;
  pid_t tid;
  pid_t pid;
  pid_t ppid;
  pid_t tracer;
  uid_t uid;
  uid_t gid;
};

/**
 * Look up a thread/process's name, ids, and scheduler state by tid.
 *
 * 中文：根据 tid 查询线程/进程的名称、各种 id 以及调度状态。
 */
// Parse the contents of /proc/<tid>/status into |process_info|.
bool GetProcessInfo(pid_t tid, ProcessInfo *process_info, std::string *error = nullptr);

/**
 * Same as GetProcessInfo() but takes an already-open /proc/<pid> directory fd,
 * letting callers avoid repeated open()/close() when querying many tids/fields.
 *
 * 中文：与 GetProcessInfo() 功能相同，但接收一个已经打开的 /proc/<pid> 目录 fd，
 * 使调用者在查询多个 tid/字段时可以避免反复 open()/close()。
 */
// Parse the contents of <fd>/status into |process_info|.
// |fd| should be an fd pointing at a /proc/<pid> directory.
bool GetProcessInfoFromProcPidFd(int fd, ProcessInfo *process_info, std::string *error = nullptr);

/**
 * Enumerate every thread id belonging to a process by listing /proc/<pid>/task/.
 * This directory exists and has one subentry per thread specifically because Linux
 * threads are implemented as ordinary tasks created via clone(CLONE_VM|...), sharing
 * the creating process's address space; the kernel surfaces each such task under its
 * thread-group leader's /proc/<pid>/task/ regardless of which thread you query it from.
 *
 * 中文：通过列出 /proc/<pid>/task/ 目录来枚举某个进程所属的所有线程 id。
 * 之所以这个目录下每个线程都有一个子项，是因为 Linux 的线程本质上是通过
 * clone(CLONE_VM|...) 创建的普通任务（task），彼此共享创建者进程的地址空间；
 * 内核会把这些任务统一挂在其线程组 leader 的 /proc/<pid>/task/ 下，无论你是
 * 从哪个线程去查询都是如此。
 */
// Fetch the list of threads from a given process's /proc/<pid> directory.
// |fd| should be an fd pointing at a /proc/<pid> directory.
template <typename Collection>
auto GetProcessTidsFromProcPidFd(int fd, Collection *out, std::string *error = nullptr) ->
    typename std::enable_if<sizeof(typename Collection::value_type) >= sizeof(pid_t), bool>::type {
  out->clear();

  // openat(fd, "task", ...) opens /proc/<pid>/task/ relative to the already-open
  // /proc/<pid> dirfd; each entry under it is one thread's tid (see the function
  // comment above for why this directory exists).
  // 中文：openat(fd, "task", ...) 相对于已经打开的 /proc/<pid> 目录 fd 打开
  // /proc/<pid>/task/ 目录；该目录下的每个条目都对应一个线程的 tid（关于这个
  // 目录为何存在，参见上面的函数注释）。
  int task_fd = openat(fd, "task", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  std::unique_ptr<DIR, int (*)(DIR *)> dir(fdopendir(task_fd), closedir);
  if (!dir) {
    if (error != nullptr) {
      *error = "failed to open task directory";
    }
    return false;
  }

  // Each directory entry name here is a decimal tid string - the kernel synthesizes
  // one entry per live thread of this process, so no /proc/<pid>/status read (or any
  // other syscall) is needed just to enumerate which threads exist.
  // 中文：这里每个目录项的名字都是十进制的 tid 字符串——内核会为该进程的每个存活
  // 线程合成一个对应的目录项，因此仅仅是枚举有哪些线程存在，并不需要读取
  // /proc/<pid>/status（也不需要任何其他系统调用）。
  struct dirent *dent;
  while ((dent = readdir(dir.get()))) {
    if (strcmp(dent->d_name, ".") != 0 && strcmp(dent->d_name, "..") != 0) {
      pid_t tid;
      if (!android::base::ParseInt(dent->d_name, &tid, 1, std::numeric_limits<pid_t>::max())) {
        if (error != nullptr) {
          *error = std::string("failed to parse task id: ") + dent->d_name;
        }
        return false;
      }

      out->insert(out->end(), tid);
    }
  }

  return true;
}

/**
 * Convenience wrapper around GetProcessTidsFromProcPidFd() that opens
 * /proc/<pid> itself given just a pid, for callers that don't already hold a
 * dirfd on it.
 *
 * 中文：对 GetProcessTidsFromProcPidFd() 的一层便捷封装，只需传入 pid，
 * 内部会自行打开 /proc/<pid>，适用于尚未持有该目录 fd 的调用者。
 */
template <typename Collection>
auto GetProcessTids(pid_t pid, Collection *out, std::string *error = nullptr) ->
    typename std::enable_if<sizeof(typename Collection::value_type) >= sizeof(pid_t), bool>::type {
  char task_path[PATH_MAX];
  if (snprintf(task_path, PATH_MAX, "/proc/%d", pid) >= PATH_MAX) {
    if (error != nullptr) {
      *error = "task path overflow (pid = " + std::to_string(pid) + ")";
    }
    return false;
  }

  // Opens /proc/<pid> itself (a kernel-maintained directory, not a real filesystem
  // path) so GetProcessTidsFromProcPidFd() can then read its "task" subdirectory.
  // 中文：打开 /proc/<pid> 本身（这是一个由内核维护的目录，并非真实的文件系统
  // 路径），以便随后 GetProcessTidsFromProcPidFd() 可以读取其中的 "task" 子目录。
  android::base::unique_fd fd(open(task_path, O_DIRECTORY | O_RDONLY | O_CLOEXEC));
  if (fd == -1) {
    if (error != nullptr) {
      *error = std::string("failed to open ") + task_path;
    }
    return false;
  }

  return GetProcessTidsFromProcPidFd(fd.get(), out, error);
}

#endif

} /* namespace procinfo */
} /* namespace android */
