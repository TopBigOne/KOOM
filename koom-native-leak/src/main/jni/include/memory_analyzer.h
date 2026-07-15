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
 * Created by lbtrace on 2021.
 *
 */

#ifndef KOOM_KOOM_NATIVE_SRC_MAIN_JNI_INCLUDE_MEMORY_ANALYZER_H_
#define KOOM_KOOM_NATIVE_SRC_MAIN_JNI_INCLUDE_MEMORY_ANALYZER_H_

#include <string>
#include <vector>

namespace kwai {
namespace leak_monitor {
/**
 * Wraps Android's system libmemunreachable.so to perform the "scan" stage of
 * the pipeline: a conservative mark-and-sweep reachability scan of this
 * process's own memory, borrowing the "trace from roots" idea used by
 * tracing garbage collectors but applied to untyped native memory (any
 * in-range value is conservatively treated as a possible pointer, since
 * there is no type metadata to know for sure).
 *
 * 中文：封装 Android 系统库 libmemunreachable.so，用来执行流水线的“scan”
 * 阶段：对本进程自身内存做一次保守式的标记-清除可达性扫描，借用了追踪式
 * 垃圾回收器中“从根开始遍历”的思路，但应用在没有类型信息的 native 内存上
 * （由于没有类型元数据可以确定，任何落在有效范围内的数值都会被保守地当作
 * 可能的指针来处理）。
 */
class MemoryAnalyzer {
 public:
  /** Dynamically loads libmemunreachable.so and resolves its entry point.
   *
   * 中文：动态加载 libmemunreachable.so 并解析其入口函数。
   */
  MemoryAnalyzer();
  /** Releases the dlopen'd libmemunreachable.so handle.
   *
   * 中文：释放 dlopen 得到的 libmemunreachable.so 句柄。
   */
  ~MemoryAnalyzer();
  /** Whether the libmemunreachable symbol was successfully resolved.
   *
   * 中文：libmemunreachable 的符号是否解析成功。
   */
  bool IsValid();
  /** Runs the reachability scan; returns unreachable (address, size) ranges.
   *
   * 中文：执行可达性扫描；返回不可达的 (地址, 大小) 区间列表。
   */
  std::vector<std::pair<uintptr_t, size_t>> CollectUnreachableMem();

 private:
  // Function pointer type matching libmemunreachable's
  // GetUnreachableMemoryString(bool, size_t), resolved at runtime via dlsym
  // since this is a private platform symbol, not something linked at build
  // time.
  // 中文：与 libmemunreachable 的 GetUnreachableMemoryString(bool, size_t)
  // 匹配的函数指针类型，通过 dlsym 在运行期解析，因为这是一个平台私有
  // 符号，并非在构建期链接的内容。
  using GetUnreachableFn = std::string (*)(bool, size_t);
  GetUnreachableFn get_unreachable_fn_;
  void *handle_;
};
}  // namespace leak_monitor
}  // namespace kwai
#endif  // KOOM_KOOM_NATIVE_SRC_MAIN_JNI_INCLUDE_MEMORY_ANALYZER_H_
