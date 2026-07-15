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
 * Created by shenvsv on 2021.
 *
 */

#ifndef APM_CALLSTACK_H
#define APM_CALLSTACK_H

#include <fast_unwind/fast_unwind.h>
#include <unistd.h>
#include <unwindstack/Unwinder.h>

#include <ostream>
#include <sstream>

#include "constant.h"
#include "util.h"

namespace koom {

using dump_java_stack_above_o_ptr = void (*)(void *, std::ostream &os, bool,
                                             bool);
using dump_java_stack_ptr = void (*)(void *, std::ostream &os);

// 封装“线程创建时刻的调用栈捕获”与“上报前的符号化”两大能力：
// - native 栈用帧指针（FP）快速回溯（FastUnwind），只在 arm64 上可靠；
// - java 栈通过反射调用 ART 内部的 art::Thread::DumpJavaStack；
// - 符号化（SymbolizePc）借助 unwindstack 库把裸 PC 地址转换成“函数名+偏移（库:偏移）”的可读字符串。
class CallStack {
  enum Type { java, native };

 private:
  // 指向 libart.so 内部 art::Thread::DumpJavaStack 的函数指针（O 之后签名多一个参数），运行时通过 dlsym 解析。
  static dump_java_stack_above_o_ptr dump_java_stack_above_o;
  static dump_java_stack_ptr dump_java_stack;
  // Android N 之前，ART 线程对象存放在这个 pthread 特有数据 key 对应的 TLS 槽里。
  static pthread_key_t pthread_key_self;
  // unwindstack 的符号化器，基于 /proc/self/maps 和目标 so 的 ELF 符号表把 PC 还原成函数名。
  static unwindstack::UnwinderFromPid *unwinder;
  // 防止符号化过程中递归重入（符号化本身可能间接触发内存分配等操作）。
  static std::atomic<bool> inSymbolize;

  static std::atomic<bool> disableJava;
  static std::atomic<bool> disableNative;

  // 保护对 ART DumpJavaStack 的调用，避免多线程并发访问导致的稳定性问题。
  static std::mutex dumpJavaLock;

 public:
  /** 根据当前 Android API level 解析 ART 内部符号（DumpJavaStack 函数指针、pthread_key_self）。 */
  static void Init();

  /** 关闭“捕获 Java 堆栈”功能（对应 Java 层 disableJavaStack）。 */
  static void DisableJava();

  /** 关闭“捕获 native 堆栈”功能（对应 Java 层 disableNativeStack）。 */
  static void DisableNative();

  /** 通过反射调用 ART 内部函数，dump 指定 ART Thread 对象当前的 Java 调用栈到 os。 */
  static void JavaStackTrace(void *thread, std::ostream &os);

  /** 基于 arm64 帧指针链做快速栈回溯，只记录裸 PC，符号化推迟到上报时按需进行。 */
  static size_t FastUnwind(uintptr_t *buf, size_t num_entries);

  /** 把一个裸 PC 地址符号化为可读的 "函数+偏移 (库:偏移)" 字符串，用于生成上报的调用栈文本。 */
  static std::string SymbolizePc(uintptr_t pc, int index);

  /** 获取当前 native 线程对应的 ART Thread 对象指针，用于后续 dump Java 栈。 */
  static void *GetCurrentThread();
};

}  // namespace koom

#endif  // APM_CALLSTACK_H
