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

#ifndef APM_KOOM_THREAD_SRC_MAIN_CPP_SRC_THREAD_HOOK_LOOPER_H_
#define APM_KOOM_THREAD_SRC_MAIN_CPP_SRC_THREAD_HOOK_LOOPER_H_

#include <jni.h>

#include <map>

#include "common/looper.h"
#include "thread_holder.h"
namespace koom {
// looper 基类提供了通用的“后台线程 + 消息队列”机制，HookLooper 在此基础上绑定一个 ThreadHolder，
// 把各个 pthread hook 回调投递过来的事件（ACTION_ADD_THREAD/JOIN/DETACH/EXIT/REFRESH）
// 分发给 ThreadHolder 的对应状态机方法处理——这样所有共享状态的读写都串行发生在同一条后台线程上，
// 无需在 hook 回调（可能来自任意业务线程，是热路径）里加锁，也不会阻塞被 hook 的原始 pthread_* 调用。
class HookLooper : public looper {
 public:
  koom::ThreadHolder *holder;
  HookLooper();
  ~HookLooper();
  void handle(int what, void *data);
  void post(int what, void *data);
};
}  // namespace koom
#endif  // APM_KOOM_THREAD_SRC_MAIN_CPP_SRC_THREAD_HOOK_LOOPER_H_