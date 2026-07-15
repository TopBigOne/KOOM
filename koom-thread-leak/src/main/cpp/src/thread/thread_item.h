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

#ifndef APM_THREAD_H
#define APM_THREAD_H
#include <string>
namespace koom {

// 描述单个被跟踪线程的完整状态快照，是 ThreadHolder 两张 map（threadMap/leakThreadMap）中的 value 类型，
// 贯穿“创建记录 -> join/detach 状态更新 -> 退出判定 -> 序列化上报”整个跟踪-报告流程。
class ThreadItem {
 public:
  // 内核线程 ID（syscall(SYS_gettid) 获得），用于上报时与 /proc、logcat 等系统视图中的线程对应。
  int id{};
  int64_t create_time{};
  // 创建时刻捕获并符号化后的调用栈文本（native + java），用于定位“是谁创建了这个线程”。
  std::string create_call_stack;
  std::string collect_mode{};
  // 是否已经处于“不会造成泄漏”的安全状态：创建时即为 detached，或后续被 join/detach 过。
  bool thread_detached{};
  long long startTime{};
  long long exitTime{};
  // 该泄漏记录是否已经上报过，避免 ReportThreadLeak 重复上报同一个线程。
  bool thread_reported{};
  // pthread_t 句柄：仅是 pthread 库在用户态维护的标识符，与内核 tid（id 字段）是两个不同的概念，
  // 在 ThreadHolder 的 map 中作为 key 使用。
  pthread_t thread_internal_id{};
  std::string name{};

  ThreadItem();
  ThreadItem(const ThreadItem &threadItem);
  void Clear();
};

#endif  // APM_THREAD_H
}