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

#ifndef APM_THREAD_HOOK_H
#define APM_THREAD_HOOK_H

#include <android/dlext.h>
#include <jni.h>
#include <pthread.h>
#include <sys/types.h>

#include "common/callstack.h"
#include "hook_looper.h"
#include "koom.h"

namespace koom {

// 整个模块 hook->跟踪 流水线的“hook”入口：负责用 xhook 对已加载/新加载的 so 做
// pthread_create/pthread_join/pthread_detach/pthread_exit 的 PLT/GOT 劫持，
// 并在各个 hook 函数中采集必要信息后投递给后台 HookLooper 处理。
class ThreadHooker {
 public:
  /** 停止 hook（目前为空实现，实际生效开关是 koom::isRunning，由 hookEnabled() 读取）。 */
  static void Stop();
  /** 启动 hook：调用 InitHook 完成对已加载 so 的全量 hook 注册，并订阅后续 dlopen 事件。 */
  static void Start();

 private:
  /**
   * 真正的线程入口跳板：pthread_create 被 hook 后，实际创建的线程会先跑到这里，
   * 采集 detach 状态、内核 tid 等信息并上报“线程已创建”事件，然后再跳转到调用方原本传入的 start_rtn。
   */
  static void HookThreadStart(void *arg);
  /** pthread_create 的替身函数：捕获创建时刻的调用栈，并把真正的入口替换成 HookThreadStart 以便二次拦截。 */
  static int HookThreadCreate(pthread_t *tidp, const pthread_attr_t *attr,
                              void *(*start_rtn)(void *), void *arg);
  /** pthread_join 的替身函数：先记录“该线程已被 join”这一状态变化事件，再调用真正的 pthread_join。 */
  static int HookThreadJoin(pthread_t t, void **return_value);
  /** pthread_detach 的替身函数：先记录“该线程已被 detach”这一状态变化事件，再调用真正的 pthread_detach。 */
  static int HookThreadDetach(pthread_t t);
  /** pthread_exit 的替身函数：记录“线程已退出”事件（用于判断是否发生泄漏），再调用真正的 pthread_exit。 */
  static void HookThreadExit(void *return_value);
  /** 对单个 so 注册 pthread_* 相关符号的 xhook，命中 ignore_libs 黑名单的库会被跳过。 */
  static bool RegisterSo(const std::string &lib, int source);
  /** 首次启动时，枚举当前进程已加载的所有 so 并对其执行 hook 注册，同时订阅后续 dlopen 回调。 */
  static void InitHook();
  /** 新 so 被 dlopen 加载时的回调，对新库补做同样的 hook 注册（保证运行期动态加载的库也被覆盖）。 */
  static void DlopenCallback(std::set<std::string> &libs, int source,
                             std::string &sourcelib);
  /** 遍历一批库依次调用 RegisterSo，并在有实际 hook 命中时统一调用 xhook_refresh 生效。 */
  static void HookLibs(std::set<std::string> &libs, int source);
  /** 是否应当记录本次 hook 事件；直接读取 koom::isRunning，为 false 时所有 hook 均直通原始实现。 */
  static bool hookEnabled();
};

// 传给被替换后的线程入口 HookThreadStart 的参数包：既保留了调用方原始的 start_rtn/arg，
// 又附带了创建时刻采集到的调用栈信息（thread_create_arg），从而在真正跳转执行用户代码前完成信息采集。
class StartRtnArg {
 public:
  void *arg;
  void *(*start_rtn)(void *);
  ThreadCreateArg *thread_create_arg;

  StartRtnArg(void *arg, long long time, void *(*start_rtn)(void *)) {
    this->arg = arg;
    this->start_rtn = start_rtn;
    thread_create_arg = new ThreadCreateArg();
    thread_create_arg->time = time;
  }
};
}  // namespace koom

#endif  // APM_THREAD_HOOK_H
