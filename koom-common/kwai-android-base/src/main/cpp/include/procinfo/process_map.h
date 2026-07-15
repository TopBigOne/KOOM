/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <functional>
#include <string>
#include <vector>

#include <android-base/file.h>

namespace android {
namespace procinfo {

/**
 * Parse an in-memory copy of a /proc/<pid>/maps-formatted text buffer line by line,
 * invoking |callback| with each mapping's (start, end, prot flags, file page offset,
 * inode, path) fields. Operates purely on the caller-owned |content| buffer (which is
 * mutated in place - newlines are overwritten with '\0') so it does not itself need
 * to allocate, matching the requirements of async-signal-safe callers.
 *
 * 中文：逐行解析内存中一份 /proc/<pid>/maps 格式的文本缓冲区副本，对每一条内存
 * 映射调用 |callback|，传入其 (起始地址、结束地址、访问权限标志、文件页偏移、
 * inode、路径) 等字段。整个过程只操作调用者传入的 |content| 缓冲区（会原地
 * 修改——换行符会被替换成 '\0'），自身不做任何内存分配，从而满足异步信号安全
 * （async-signal-safe）调用者的要求。
 */
template <class CallbackType> bool ReadMapFileContent(char *content, const CallbackType &callback) {
  uint64_t start_addr;
  uint64_t end_addr;
  uint16_t flags;
  uint64_t pgoff;
  ino_t inode;
  char *next_line = content;
  char *p;

  auto pass_space = [&]() {
    if (*p != ' ') {
      return false;
    }
    while (*p == ' ') {
      p++;
    }
    return true;
  };

  auto pass_xdigit = [&]() {
    if (!isxdigit(*p)) {
      return false;
    }
    do {
      p++;
    } while (isxdigit(*p));
    return true;
  };

  while (next_line != nullptr && *next_line != '\0') {
    p = next_line;
    next_line = strchr(next_line, '\n');
    if (next_line != nullptr) {
      *next_line = '\0';
      next_line++;
    }
    // Parse line like: 00400000-00409000 r-xp 00000000 fc:00 426998  /usr/lib/gvfs/gvfsd-http
    char *end;
    // start_addr
    start_addr = strtoull(p, &end, 16);
    if (end == p || *end != '-') {
      return false;
    }
    p = end + 1;
    // end_addr
    end_addr = strtoull(p, &end, 16);
    if (end == p) {
      return false;
    }
    p = end;
    if (!pass_space()) {
      return false;
    }
    // flags
    flags = 0;
    if (*p == 'r') {
      flags |= PROT_READ;
    } else if (*p != '-') {
      return false;
    }
    p++;
    if (*p == 'w') {
      flags |= PROT_WRITE;
    } else if (*p != '-') {
      return false;
    }
    p++;
    if (*p == 'x') {
      flags |= PROT_EXEC;
    } else if (*p != '-') {
      return false;
    }
    p++;
    if (*p != 'p' && *p != 's') {
      return false;
    }
    p++;
    if (!pass_space()) {
      return false;
    }
    // pgoff
    pgoff = strtoull(p, &end, 16);
    if (end == p) {
      return false;
    }
    p = end;
    if (!pass_space()) {
      return false;
    }
    // major:minor
    if (!pass_xdigit() || *p++ != ':' || !pass_xdigit() || !pass_space()) {
      return false;
    }
    // inode
    inode = strtoull(p, &end, 10);
    if (end == p) {
      return false;
    }
    p = end;

    if (*p != '\0' && !pass_space()) {
      return false;
    }

    // filename
    callback(start_addr, end_addr, flags, pgoff, inode, p);
  }
  return true;
}

/**
 * Read an arbitrary maps-formatted file (e.g. "/proc/<pid>/maps") fully into a
 * std::string, then parse it via ReadMapFileContent(). Not async-signal-safe (it
 * allocates); for that case use ReadMapFileAsyncSafe() declared below instead.
 *
 * 中文：将任意 maps 格式的文件（例如 "/proc/<pid>/maps"）完整读入一个
 * std::string，再通过 ReadMapFileContent() 解析。该函数不是异步信号安全的
 * （因为会做内存分配）；若需要异步信号安全，请改用下面声明的
 * ReadMapFileAsyncSafe()。
 */
inline bool ReadMapFile(const std::string &map_file,
                        const std::function<void(uint64_t, uint64_t, uint16_t, uint64_t, ino_t,
                                                 const char *)> &callback) {
  std::string content;
  if (!android::base::ReadFileToString(map_file, &content)) {
    return false;
  }
  return ReadMapFileContent(&content[0], callback);
}

/**
 * Read and parse a given process's memory map from /proc/<pid>/maps - the kernel's
 * file-based view of that process's virtual memory layout (segment ranges,
 * permissions, backing file/inode), obtainable without ptrace or special privilege.
 *
 * 中文：从 /proc/<pid>/maps 读取并解析指定进程的内存映射——这是内核以文件形式
 * 暴露的该进程虚拟内存布局视图（各内存段的范围、权限、所对应的文件/inode），
 * 获取时无需 ptrace，也不需要特殊权限。
 */
inline bool ReadProcessMaps(pid_t pid,
                            const std::function<void(uint64_t, uint64_t, uint16_t, uint64_t, ino_t,
                                                     const char *)> &callback) {
  return ReadMapFile("/proc/" + std::to_string(pid) + "/maps", callback);
}

struct MapInfo {
  uint64_t start;
  uint64_t end;
  uint16_t flags;
  uint64_t pgoff;
  ino_t inode;
  std::string name;

  MapInfo(uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, ino_t inode,
          const char *name)
      : start(start), end(end), flags(flags), pgoff(pgoff), inode(inode), name(name) {}
};

/**
 * Convenience overload of ReadProcessMaps() that collects every mapping into a
 * vector<MapInfo> instead of requiring the caller to supply a callback.
 *
 * 中文：ReadProcessMaps() 的一个便捷重载版本，将每条内存映射收集到一个
 * vector<MapInfo> 中，调用者无需自行提供回调函数。
 */
inline bool ReadProcessMaps(pid_t pid, std::vector<MapInfo> *maps) {
  return ReadProcessMaps(
      pid, [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, ino_t inode,
               const char *name) { maps->emplace_back(start, end, flags, pgoff, inode, name); });
}

/**
 * Async-signal-safe variant of ReadMapFile(): reads/parses a maps file using only a
 * caller-supplied fixed buffer, performing no heap allocation, so it can safely be
 * called from a signal handler or crash-dump path (see async_safe_log.cpp for the
 * broader rationale behind avoiding allocation in such contexts).
 *
 * 中文：ReadMapFile() 的异步信号安全（async-signal-safe）版本：仅使用调用者
 * 提供的固定缓冲区来读取/解析 maps 文件，不做任何堆内存分配，因此可以安全地在
 * 信号处理函数或 crash-dump 路径中调用（关于此类场景下为何要避免内存分配的
 * 详细原因，可参见 async_safe_log.cpp）。
 */
bool ReadMapFileAsyncSafe(const char *map_file, void *buffer, size_t buffer_size,
                          const std::function<void(uint64_t, uint64_t, uint16_t, uint64_t, ino_t,
                                                   const char *)> &callback);

} /* namespace procinfo */
} /* namespace android */
