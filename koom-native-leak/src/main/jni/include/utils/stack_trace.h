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

#ifndef KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_STACK_TRACE_H_
#define KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_STACK_TRACE_H_

#include <stdint.h>
#include <stdlib.h>

#include <cstddef>
#include <iostream>

#include "constants.h"

// Forces the "initial-exec" TLS access model instead of the default
// "global-dynamic" one, trading TLS access flexibility (won't work for code
// loaded via dlopen after startup, in general) for faster reads, since these
// thread-local unwind-state variables are read on every hooked allocation.
// 中文：强制使用“initial-exec”TLS 访问模型，而不是默认的
// “global-dynamic”模型，用 TLS 访问的灵活性（一般来说，对启动之后才通过
// dlopen 加载的代码不适用）换取更快的读取速度，因为这些线程局部的展开
// 状态变量会在每一次被 hook 的分配中被读取。
#define FAST_UNWIND_TLS_INITIAL_EXEC \
  __thread __attribute__((tls_model("initial-exec")))

#ifndef KWAI_EXPORT
#define KWAI_EXPORT __attribute__((visibility("default")))
#endif

/**
 * Provides the fast frame-pointer-chain backtrace capture used by
 * LeakMonitor::RegisterAlloc on every hooked allocation (the "record" stage
 * of the pipeline). See stack_trace.cpp for why frame-pointer walking is
 * used instead of a DWARF/.eh_frame-based unwinder.
 *
 * 中文：提供基于帧指针链的快速调用栈捕获，供 LeakMonitor::RegisterAlloc
 * 在每一次被 hook 的分配（流水线的“record”阶段）中调用。关于为什么使用
 * 帧指针遍历而不是基于 DWARF/.eh_frame 的展开器，参见 stack_trace.cpp。
 */
class StackTrace {
 public:
  /** Captures up to num_entries backtrace PCs into buf; returns frame count.
   *
   * 中文：最多把 num_entries 个调用栈 PC 捕获进 buf；返回实际捕获的帧数。
   */
  static size_t FastUnwind(uintptr_t *buf, size_t num_entries);
};

#endif  // KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_STACK_TRACE_H_
