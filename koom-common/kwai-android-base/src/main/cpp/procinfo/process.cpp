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

#include <procinfo/process.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include <android-base/unique_fd.h>

using android::base::unique_fd;

namespace android {
namespace procinfo {

/**
 * Look up a single thread/process's info by tid, using /proc/<tid> as the source.
 * This is the public entry point most callers use to inspect another thread without
 * needing ptrace or root: the kernel exposes live process state as plain files.
 *
 * 中文：根据 tid 查询单个线程/进程的信息，数据来源是 /proc/<tid>。这是大多数调用者
 * 用来查看其他线程信息的公共入口：无需 ptrace 或 root 权限，因为内核会把存活进程的
 * 状态以普通文件的形式暴露出来。
 */
bool GetProcessInfo(pid_t tid, ProcessInfo *process_info, std::string *error) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d", tid);

  // /proc/<tid> works for any tid (thread or process) because Linux threads are just
  // processes created via clone(CLONE_VM|...) sharing an address space with their
  // group leader - the kernel gives every schedulable task its own /proc entry.
  // Opening it as a directory fd (no special syscalls/root needed) lets us later use
  // openat() below to read files "status" from the same task's /proc.
  // 中文：/proc/<tid> 对任意 tid（线程或进程）都适用，因为 Linux 的线程本质上就是
  // 通过 clone(CLONE_VM|...) 创建、并与其线程组 leader 共享地址空间的进程——内核
  // 会为每个可调度的任务（task）分配独立的 /proc 目录项。以目录 fd 的形式打开它
  // （不需要特殊的系统调用或 root 权限），使得下面可以用 openat() 从同一个任务的
  // /proc 目录中读取 "status" 文件。
  unique_fd dirfd(open(path, O_DIRECTORY | O_RDONLY));
  if (dirfd == -1) {
    if (error != nullptr) {
      *error = std::string("failed to open ") + path;
    }
    return false;
  }

  return GetProcessInfoFromProcPidFd(dirfd.get(), process_info, error);
}

/**
 * Map the single-character "State:" field from /proc/<pid>/status (R/S/D/T/Z/...)
 * to our ProcessState enum. The kernel encodes scheduler state this way in the
 * status file rather than through a syscall return value.
 *
 * 中文：将 /proc/<pid>/status 中单字符的 "State:" 字段（R/S/D/T/Z/...）映射到
 * 我们自己定义的 ProcessState 枚举。内核选择用 status 文件里的这种编码方式来表达
 * 调度状态，而不是通过某个系统调用的返回值。
 */
static ProcessState parse_state(const char *state) {
  switch (*state) {
  case 'R':
    return kProcessStateRunning;
  case 'S':
    return kProcessStateSleeping;
  case 'D':
    return kProcessStateUninterruptibleWait;
  case 'T':
    return kProcessStateStopped;
  case 'Z':
    return kProcessStateZombie;
  default:
    return kProcessStateUnknown;
  }
}

/**
 * Parse /proc/<pid>/status (given an already-open fd on the /proc/<pid> directory)
 * into a ProcessInfo struct. This is how we read kernel-held process/thread metadata
 * (name, ids, state) from userspace without needing a dedicated syscall for each field -
 * the kernel formats it all as text for us to scan.
 *
 * 中文：在已经打开 /proc/<pid> 目录 fd 的前提下，解析 /proc/<pid>/status 文件，
 * 并填充到 ProcessInfo 结构体中。这就是用户态程序读取内核维护的进程/线程元数据
 * （名称、各种 id、状态）的方式——不需要为每个字段单独设计系统调用，内核已经把
 * 这些信息格式化成文本，供我们直接扫描解析。
 */
bool GetProcessInfoFromProcPidFd(int fd, ProcessInfo *process_info, std::string *error) {
  // openat() relative to the /proc/<pid> dirfd reads that specific task's status file;
  // this is the same "everything is a file" mechanism that exposes kernel process state
  // (no root, no special syscall) - here for the "status" pseudo-file specifically.
  // 中文：相对于 /proc/<pid> 的目录 fd 调用 openat()，读取该任务对应的 status 文件；
  // 这正是内核用来暴露进程状态的"一切皆文件"机制的具体体现（不需要 root，也不需要
  // 特殊系统调用），这里针对的是 "status" 这个伪文件。
  int status_fd = openat(fd, "status", O_RDONLY | O_CLOEXEC);

  if (status_fd == -1) {
    if (error != nullptr) {
      *error = "failed to open status fd in GetProcessInfoFromProcPidFd";
    }
    return false;
  }

  std::unique_ptr<FILE, decltype(&fclose)> fp(fdopen(status_fd, "r"), fclose);
  if (!fp) {
    if (error != nullptr) {
      *error = "failed to open status file in GetProcessInfoFromProcPidFd";
    }
    close(status_fd);
    return false;
  }

  int field_bitmap = 0;
  static constexpr int finished_bitmap = 255;
  char *line = nullptr;
  size_t len = 0;

  // /proc/<pid>/status is a kernel-generated text file, one "Header:\tvalue" pair per
  // line; we scan until we've collected every field we care about (bitmap all set).
  // 中文：/proc/<pid>/status 是内核生成的文本文件，每一行都是一个
  // "Header:\tvalue" 键值对；我们持续扫描，直到收集齐所有关心的字段
  // （即 bitmap 所有位都被置位）为止。
  while (getline(&line, &len, fp.get()) != -1 && field_bitmap != finished_bitmap) {
    char *tab = strchr(line, '\t');
    if (tab == nullptr) {
      continue;
    }

    size_t header_len = tab - line;
    std::string header = std::string(line, header_len);
    if (header == "Name:") {
      std::string name = line + header_len + 1;

      // line includes the trailing newline.
      name.pop_back();
      process_info->name = std::move(name);

      field_bitmap |= 1;
    } else if (header == "Pid:") {
      process_info->tid = atoi(tab + 1);
      field_bitmap |= 2;
    } else if (header == "Tgid:") {
      process_info->pid = atoi(tab + 1);
      field_bitmap |= 4;
    } else if (header == "PPid:") {
      process_info->ppid = atoi(tab + 1);
      field_bitmap |= 8;
    } else if (header == "TracerPid:") {
      process_info->tracer = atoi(tab + 1);
      field_bitmap |= 16;
    } else if (header == "Uid:") {
      process_info->uid = atoi(tab + 1);
      field_bitmap |= 32;
    } else if (header == "Gid:") {
      process_info->gid = atoi(tab + 1);
      field_bitmap |= 64;
    } else if (header == "State:") {
      process_info->state = parse_state(tab + 1);
      field_bitmap |= 128;
    }
  }

  free(line);
  return field_bitmap == finished_bitmap;
}

} /* namespace procinfo */
} /* namespace android */
