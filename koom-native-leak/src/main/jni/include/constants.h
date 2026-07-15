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

#ifndef KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_CONSTANTS_H_
#define KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_CONSTANTS_H_

#include <string>

// Max frames captured per allocation by StackTrace::FastUnwind; bounds the
// per-AllocRecord memory cost since this runs on every hooked allocation.
// 中文：StackTrace::FastUnwind 为每次分配捕获的最大帧数；由于这段代码运行
// 在每一次被 hook 的分配上，这个上限用来控制每个 AllocRecord 的内存开销。
const uint32_t kMaxBacktraceSize = 12;
// Matches Linux's thread name length limit (prctl(PR_GET_NAME/PR_SET_NAME)
// caps names at 16 bytes including the NUL terminator).
// 中文：与 Linux 的线程名长度限制保持一致（prctl(PR_GET_NAME/PR_SET_NAME)
// 将线程名限制为 16 字节，包含结尾的 NUL 终止符）。
const uint32_t kMaxThreadNameLen = 16;
// Minimum allocation size (bytes) tracked by default; smaller allocations
// are skipped by LeakMonitor::OnMonitor to bound hook overhead.
// 中文：默认被跟踪的最小分配字节数；更小的分配会被 LeakMonitor::OnMonitor
// 跳过，以控制 hook 的开销。
const uint32_t kDefaultAllocThreshold = 15;

#endif // KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_CONSTANTS_H_
