/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <procinfo/process_map.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <procinfo/process.h>

namespace android {
namespace procinfo {

/**
 * Read and parse a /proc/<pid>/maps-style file using only a caller-supplied fixed
 * buffer (no malloc/std::string allocation), so this can safely run from contexts
 * such as a signal handler or crash dumper where the heap may be unusable/locked.
 * Each parsed line is handed to |callback| as it's found, incrementally.
 *
 * 中文：仅使用调用者提供的固定缓冲区来读取并解析 /proc/<pid>/maps 风格的文件
 * （不做 malloc/std::string 之类的内存分配），因此可以安全地在信号处理函数或
 * crash dumper 等堆内存可能不可用/被锁定的场景下运行。每解析出一行，就立即
 * 增量地回调 |callback|。
 */
bool ReadMapFileAsyncSafe(const char *map_file, void *buffer, size_t buffer_size,
                          const std::function<void(uint64_t, uint64_t, uint16_t, uint64_t, ino_t,
                                                   const char *)> &callback) {
  if (buffer == nullptr || buffer_size == 0) {
    return false;
  }

  // /proc/<pid>/maps exposes the kernel's view of a process's virtual memory
  // mappings (segments, permissions, backing file/inode) as a plain text file -
  // the same "everything is a file" mechanism used elsewhere in /proc, requiring
  // no ptrace or special privilege to inspect another process's memory layout.
  // 中文：/proc/<pid>/maps 以纯文本文件的形式暴露内核对该进程虚拟内存映射的视图
  // （各内存段的范围、访问权限、所对应的文件/inode）——这与 /proc 下其他地方使用的
  // "一切皆文件"机制相同，查看其他进程的内存布局既不需要 ptrace，也不需要特殊权限。
  int fd = open(map_file, O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    return false;
  }

  char *char_buffer = reinterpret_cast<char *>(buffer);
  size_t start = 0;
  size_t read_bytes = 0;
  char *line = nullptr;
  bool read_complete = false;
  while (true) {
    // Raw read() into the caller's buffer (retried on EINTR) instead of buffered
    // stdio (fopen/getline) - stdio may allocate internally, which is unsafe here.
    // 中文：直接对调用者提供的缓冲区执行 read()（遇到 EINTR 会重试），而不是使用
    // 带缓冲的 stdio（如 fopen/getline）——因为 stdio 内部可能会做内存分配，
    // 这在当前场景下是不安全的。
    ssize_t bytes =
        TEMP_FAILURE_RETRY(read(fd, char_buffer + read_bytes, buffer_size - read_bytes - 1));
    if (bytes <= 0) {
      if (read_bytes == 0) {
        close(fd);
        return bytes == 0;
      }
      // Treat the last piece of data as the last line.
      char_buffer[start + read_bytes] = '\n';
      bytes = 1;
      read_complete = true;
    }
    read_bytes += bytes;

    while (read_bytes > 0) {
      char *newline = reinterpret_cast<char *>(memchr(&char_buffer[start], '\n', read_bytes));
      if (newline == nullptr) {
        break;
      }
      *newline = '\0';
      line = &char_buffer[start];
      start = newline - char_buffer + 1;
      read_bytes -= newline - line + 1;

      // Ignore the return code, errors are okay.
      ReadMapFileContent(line, callback);
    }

    if (read_complete) {
      close(fd);
      return true;
    }

    if (start == 0 && read_bytes == buffer_size - 1) {
      // The buffer provided is too small to contain this line, give up
      // and indicate failure.
      close(fd);
      return false;
    }

    // Copy any leftover data to the front  of the buffer.
    if (start > 0) {
      if (read_bytes > 0) {
        memmove(char_buffer, &char_buffer[start], read_bytes);
      }
      start = 0;
    }
  }
}

} /* namespace procinfo */
} /* namespace android */
