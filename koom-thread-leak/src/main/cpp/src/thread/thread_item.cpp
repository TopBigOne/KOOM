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

#include "thread_item.h"

namespace koom {

/** 默认构造函数：所有字段使用类内默认初始值（见 thread_item.h 中的 {} 初始化）。 */
ThreadItem::ThreadItem() = default;

/**
 * 拷贝构造函数：用于 ThreadHolder::ExitThread 中把线程状态从 threadMap 拷贝进 leakThreadMap
 * （map 的 operator[] 赋值需要可拷贝的 value 类型）。逐字段深拷贝，包括调用栈这类字符串成员。
 */
ThreadItem::ThreadItem(const ThreadItem &threadItem) {
  this->create_time = threadItem.create_time;
  this->id = threadItem.id;
  this->create_call_stack.assign(threadItem.create_call_stack);
  this->thread_detached = threadItem.thread_detached;
  this->thread_internal_id = threadItem.thread_internal_id;
  this->startTime = threadItem.startTime;
  this->exitTime = threadItem.exitTime;
  this->thread_reported = threadItem.thread_reported;
  this->name.assign(threadItem.name);
  this->collect_mode.assign(threadItem.collect_mode);
}

/**
 * 重置所有字段为初始值。在 ThreadHolder::AddThread 中，
 * 对同一个 pthread_t 槽位（可能因为 pthread_t 被系统复用）重新登记新线程前先调用，避免脏数据残留。
 */
void ThreadItem::Clear() {
  this->id = 0;
  this->create_time = 0;
  this->create_call_stack.clear();
  this->thread_internal_id = 0;
  this->startTime = 0LL;
  this->thread_detached = false;
  this->exitTime = 0LL;
  this->thread_reported = false;
  this->name.clear();
  this->collect_mode.clear();
}
}  // namespace koom