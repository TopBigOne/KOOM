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

#ifndef APM_RESOURCEDATA_H
#define APM_RESOURCEDATA_H

#include <map>

#include "common/callstack.h"
#include "common/log.h"
#include "common/util.h"
#include "loop_item.h"
#include "rapidjson/writer.h"
#include "thread_item.h"

namespace koom {

// 本模块“跟踪”阶段的状态机核心：只在后台 HookLooper 工作线程上被调用（因此内部无需加锁），
// 用 pthread_t 作为 key 维护两张表——threadMap 保存当前存活且仍处于 joinable 状态的线程，
// leakThreadMap 保存已确认“退出时既未 join 也未 detach”的疑似泄漏线程，等待延迟后统一上报。
class ThreadHolder {
 public:
  /**
   * 处理 ACTION_ADD_THREAD：记录一个刚创建线程的初始状态（内核 tid、pthread_t、是否 detached、
   * 创建时间、创建调用栈）。若 isThreadDetached 为 true，说明创建时就已经是 detached 线程，
   * 天然不会发生“退出未回收”的泄漏，后续 ExitThread 会据此跳过泄漏判定。
   */
  void AddThread(int tid, pthread_t pthread, bool isThreadDetached,
                 int64_t start_time, ThreadCreateArg* create_arg);
  /**
   * 处理 ACTION_JOIN_THREAD：POSIX 语义中，pthread_join 会等待目标线程结束并回收其资源，
   * 等价于把该线程标记为“已被正确回收”，因此这里把 thread_detached 置为 true
   * （复用同一个标志表示“不会再泄漏”，而不严格区分 join 与 detach）。
   */
  void JoinThread(pthread_t threadId);
  /**
   * 处理 ACTION_EXIT_THREAD：线程真正退出（调用了 pthread_exit）时触发。
   * 这里检查该线程是否已经被 join 或 detach 过（thread_detached 标志）——
   * 如果一个 joinable 线程退出时既未被 join 也未被 detach，其内核线程资源
   * （线程描述符、内核栈等）将无人回收、一直占用到进程结束，这就是本模块要检测并上报的"线程泄漏"，
   * 于是把它从 threadMap 移入 leakThreadMap，等待 ReportThreadLeak 延迟上报。
   */
  void ExitThread(pthread_t threadId, std::string& threadName, long long int i);
  /**
   * 处理 ACTION_DETACH_THREAD：pthread_detach 把一个 joinable 线程转为退出后自动回收资源、
   * 不能再被 join 的状态，等价于标记“该线程不会造成泄漏”。
   */
  void DetachThread(pthread_t threadId);
  /**
   * 处理 ACTION_REFRESH：扫描 leakThreadMap，对退出时间已超过 threadLeakDelay 阈值、
   * 且尚未上报过的疑似泄漏线程，序列化为 JSON 并通过 JavaCallback 上报给 Java 层，
   * 是整条 hook->跟踪->报告流水线的最后一步。
   */
  void ReportThreadLeak(long long time);

 private:
  // 已确认发生泄漏、等待延迟上报的线程集合。
  std::map<pthread_t, ThreadItem> leakThreadMap;
  // 当前仍处于跟踪中（存活或状态未最终判定）的线程集合。
  std::map<pthread_t, ThreadItem> threadMap;
  // 把单个线程的信息（tid、创建/开始/结束时间、名称、创建调用栈）写成一个 JSON object。
  void WriteThreadJson(rapidjson::Writer<rapidjson::StringBuffer>& writer,
                       ThreadItem& thread_item);
  void Clear() {
    leakThreadMap.clear();
    threadMap.clear();
  }
};
}  // namespace koom
#endif  // APM_RESOURCEDATA_H
