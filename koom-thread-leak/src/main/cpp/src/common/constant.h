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

#ifndef APM_RESDETECTOR_CONSTANT_H
#define APM_RESDETECTOR_CONSTANT_H

#include <string>
#include <vector>

namespace koom {

namespace Constant {
// 强制内联，用于 HookThreadStart 等对性能敏感、且需要避免多一层栈帧影响调用栈观感的函数。
#define ALWAYS_INLINE __attribute__((always_inline))

// 帧指针回溯（FastUnwind）时最多采集的栈帧数，也是 ThreadCreateArg::pc 数组的长度上限，
// 太小会截断关键调用栈，太大会增加每次 pthread_create 的开销，18 是二者的折中值。
const static int kMaxCallStackDepth = 18;
// 标记某次对 so 的 hook 注册是发生在“模块初始化时的全量扫描”，区别于运行期新 dlopen 触发的增量 hook。
const static int kDlopenSourceInit = 0;
}  // namespace Constant
}  // namespace koom
#endif  // APM_RESDETECTOR_CONSTANT_H
