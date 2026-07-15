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

#ifndef KOOM_KOOM_THREAD_LEAK_SRC_MAIN_CPP_SRC_THREAD_LOOP_ITEM_H_
#define KOOM_KOOM_THREAD_LEAK_SRC_MAIN_CPP_SRC_THREAD_LOOP_ITEM_H_
namespace koom {
// HookLooper::handle 的 switch-case 用这些枚举值区分投递到队列里的消息类型，
// 分别对应 pthread_create/join/detach/exit 四类 hook 事件，以及触发泄漏扫描的 REFRESH 事件。
enum HookAction {
  ACTION_ADD_THREAD,
  ACTION_START_THREAD,
  ACTION_JOIN_THREAD,
  ACTION_EXIT_THREAD,
  ACTION_DETACH_THREAD,
  ACTION_INIT,
  ACTION_REFRESH,
  ACTION_SET_NAME,
};

// 在 HookThreadCreate（创建者线程上下文）中采集、随 StartRtnArg 一起传递到新线程的
// “创建现场”信息：时间戳、native 调用栈裸 PC 序列、Java 堆栈文本，最终随 ACTION_ADD_THREAD
// 事件流转到 ThreadHolder::AddThread 完成符号化和记录。
class ThreadCreateArg {
 public:
  int64_t time;
  int64_t stack_time;
  std::ostringstream java_stack;
  // FastUnwind（帧指针回溯）填充的裸 PC 序列，尚未符号化，符号化被推迟到真正需要生成报告时才做。
  uintptr_t pc[koom::Constant::kMaxCallStackDepth]{};
  ThreadCreateArg() {}
  ~ThreadCreateArg() { memset(pc, 0, sizeof(pc)); }
};

// ACTION_REFRESH 事件携带的负载：仅需要触发扫描时的时间戳，用于和 leakThreadMap 中各线程的
// 退出时间比较，判断是否已超过 threadLeakDelay 宽限期。
struct SimpleHookInfo {
  long long time;
  SimpleHookInfo(long long time) { this->time = time; }
};
// ACTION_JOIN_THREAD / ACTION_DETACH_THREAD 事件的通用负载：标识具体是哪个 pthread_t 发生了状态变化。
struct HookInfo {
  pthread_t thread_id;
  long long time;
  HookInfo(pthread_t threadId, long long time) {
    this->thread_id = threadId;
    this->time = time;
  }
};
// ACTION_EXIT_THREAD 事件的负载：除了 pthread_t 外还携带内核 tid 和线程名，
// 用于 ExitThread 判定泄漏、以及生成报告时展示更友好的线程标识。
struct HookExitInfo {
  pthread_t thread_id;
  long long time;
  int tid;
  std::string threadName;
  HookExitInfo(pthread_t threadId, int tid, char *threadName, long long time) {
    this->thread_id = threadId;
    this->tid = tid;
    this->threadName.assign(threadName);
    this->time = time;
  }
};

// ACTION_ADD_THREAD 事件的负载：把新线程的内核 tid、pthread_t 句柄、初始 detach 状态
// 以及创建现场信息（ThreadCreateArg）打包在一起，供 ThreadHolder::AddThread 登记初始状态。
struct HookAddInfo {
 public:
  int tid;
  int64_t time;
  pthread_t pthread;
  bool is_thread_detached;
  ThreadCreateArg *create_arg;

  HookAddInfo(int tid, long long time, pthread_t pthread, bool isThreadDetached,
              ThreadCreateArg *thread_create_arg) {
    this->tid = tid;
    this->time = time;
    this->pthread = pthread;
    this->is_thread_detached = isThreadDetached;
    this->create_arg = thread_create_arg;
  };
};
}  // namespace koom
#endif  // KOOM_KOOM_THREAD_LEAK_SRC_MAIN_CPP_SRC_THREAD_LOOP_ITEM_H_
