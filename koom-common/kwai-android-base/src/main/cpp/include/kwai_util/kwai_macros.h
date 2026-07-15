/*
 * Copyright (c) 2020. Kwai, Inc. All rights reserved.
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
 * Created by Qiushi Xue <xueqiushi@kuaishou.com> on 2020.
 *
 */

#ifndef KWAI_MACROS_H
#define KWAI_MACROS_H

// Forces a symbol to be visible outside this shared object (overriding a
// default "-fvisibility=hidden" build setting) - needed for functions in this
// koom-common utility layer that other KOOM modules (koom-java-leak, koom-native-leak,
// koom-thread-leak, koom-fast-dump) look up across .so boundaries, e.g. via dlsym().
// 中文：强制让某个符号在本共享库（.so）之外也可见（覆盖默认的
// "-fvisibility=hidden" 编译设置）——这是 koom-common 工具层里的函数所需要的，
// 因为其他 KOOM 模块（koom-java-leak、koom-native-leak、koom-thread-leak、
// koom-fast-dump）需要跨 .so 边界查找它们，例如通过 dlsym()。
#define KWAI_EXPORT __attribute__((visibility("default")))
// Hints the compiler to inline this function even at -O0/without LTO, for tiny hot
// helpers where a real call would be measurable overhead (e.g. in signal-handler
// paths where every extra frame/register spill matters).
// 中文：提示编译器即使在 -O0（无优化）或未开启 LTO 的情况下，也要内联这个函数；
// 适用于那些体量很小、调用频率很高的辅助函数，此时一次真实的函数调用开销是可
// 被度量到的（例如在信号处理路径中，每多一个栈帧/寄存器溢出都很关键）。
#define ALWAYS_INLINE __attribute__((always_inline))

#define KWAI_OVERRIDE

#endif // KWAI_MACROS_H