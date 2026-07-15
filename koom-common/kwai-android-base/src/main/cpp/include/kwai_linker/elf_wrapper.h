// Copyright 2020 Kwai, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//         http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: lbtrace

#ifndef KOOM_KWAI_ANDROID_BASE_SRC_MAIN_CPP_INCLUDE_KWAI_LINKER_ELF_WRAPPER_H_
#define KOOM_KWAI_ANDROID_BASE_SRC_MAIN_CPP_INCLUDE_KWAI_LINKER_ELF_WRAPPER_H_

#include <fcntl.h>
#include <log/log.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

namespace kwai {
namespace linker {
/**
 * Abstracts over "where the ELF bytes physically live" (a file to mmap, or an
 * in-memory blob) so ElfReader can parse either uniformly via Start()/Size(),
 * without caring whether the data came from disk or from decompressing
 * .gnu_debugdata.
 *
 * 中文：抽象出"ELF 字节数据实际存放在哪里"这一细节（可以是需要 mmap 的文件，也可以
 * 是一段内存中的数据块），这样 ElfReader 就可以统一通过 Start()/Size() 来解析，而
 * 不必关心数据究竟来自磁盘文件，还是来自解压 .gnu_debugdata 得到的结果。
 */
class ElfWrapper {
 public:
  ElfWrapper() : start_(nullptr), size_(0) {}
  virtual ~ElfWrapper() {}

  virtual bool IsValid() { return false; }
  ElfW(Ehdr) * Start() { return reinterpret_cast<ElfW(Ehdr) *>(start_); }
  size_t Size() { return size_; }

 protected:
  void *start_;
  size_t size_;
};

/**
 * Read ELF from so file.
 * Opens and mmaps a library file from disk directly - independent of whatever the
 * dynamic linker may or may not have already mapped for it - so ElfReader can parse
 * its sections even for libraries the linker refuses to dlopen() for this process.
 *
 * 中文：直接从磁盘打开并 mmap 库文件——不依赖动态链接器是否已经为它建立过映射——
 * 这样即使链接器拒绝为当前进程 dlopen() 某个库，ElfReader 仍然可以解析它的
 * section 内容。
 */
class FileElfWrapper : public ElfWrapper {
 public:
  explicit FileElfWrapper(const char *name) : fd_(-1) {
    if (!name) {
      return;
    }
    // Open the library file by path directly, bypassing the dynamic linker entirely
    // (no dlopen involved, so no linker namespace check can block this).
    // 中文：直接按路径打开库文件，完全绕过动态链接器（没有经过 dlopen，因此不会
    // 受到 linker 命名空间检查的限制）。
    fd_ = open(name, O_RDONLY);
    if (fd_ < 0) {
      ALOGE("open %s fail, errno %d", name, errno);
      return;
    }

    // lseek to the end is a cheap way to get the file size without a separate stat()
    // call.
    // 中文：将文件指针 lseek 到末尾是一种低成本获取文件大小的方式，无需额外调用
    // stat()。
    size_ = lseek(fd_, 0, SEEK_END);
    if (size_ <= 0) {
      ALOGE("lseek fail or size %d errno %d", size_, errno);
      return;
    }

    // mmap the whole file read-only so ElfReader can treat file offsets as direct
    // memory offsets, rather than manually seeking/reading each field.
    // 中文：将整个文件以只读方式 mmap 进内存，这样 ElfReader 就可以把文件偏移量
    // 当作内存偏移量直接使用，而不必逐个字段地手动 seek/read。
    start_ = reinterpret_cast<ElfW(Ehdr) *>(
        mmap(0, size_, PROT_READ, MAP_SHARED, fd_, 0));
    if (start_ == MAP_FAILED) {
      ALOGE("mmap size %d fail, errno %d", size_, errno);
      return;
    }
  }

  ~FileElfWrapper() {
    if (start_ != MAP_FAILED && size_ > 0) {
      munmap(reinterpret_cast<void *>(start_), size_);
    }
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  bool IsValid() { return fd_ >= 0 && start_ != MAP_FAILED && size_ > 0; }

 private:
  int fd_;
};

/**
 * Read ELF from memory data.
 * Wraps an ELF image that already exists in memory (e.g. the buffer produced by
 * decompressing .gnu_debugdata) so ElfReader can parse it the same way it parses a
 * file-backed ELF, without needing a real file/fd at all.
 *
 * 中文：封装一段已经存在于内存中的 ELF 镜像（例如解压 .gnu_debugdata 得到的
 * 数据缓冲区），使得 ElfReader 可以像解析基于文件的 ELF 一样解析它，完全不需要
 * 真实的文件或文件描述符。
 */
class MemoryElfWrapper : public ElfWrapper {
 public:
  explicit MemoryElfWrapper(std::string &elf_data) {
    if (elf_data.empty()) {
      return;
    }
    elf_data_ = std::move(elf_data);
    start_ = elf_data_.data();
    size_ = elf_data_.size();
  }

  bool IsValid() { return start_ && size_ > 0; }

 private:
  std::string elf_data_;
};
}  // namespace linker
}  // namespace kwai
#endif  // KOOM_KWAI_ANDROID_BASE_SRC_MAIN_CPP_INCLUDE_KWAI_LINKER_ELF_WRAPPER_H_
