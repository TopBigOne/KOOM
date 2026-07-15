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

#include "hook_looper.h"

#include "koom.h"
#include "loop_item.h"
namespace koom {
const char *looper_tag = "koom-hook-looper";

/** 构造时创建自己专属的 ThreadHolder，用于保存本次运行期间的所有线程状态。 */
HookLooper::HookLooper() : looper() { this->holder = new koom::ThreadHolder(); }

/** 析构时释放 ThreadHolder（连同其内部的 threadMap/leakThreadMap）。 */
HookLooper::~HookLooper() { delete this->holder; }

/**
 * 后台工作线程上的消息分发中心：把 what 对应的事件路由到 ThreadHolder 具体的状态机方法，
 * 这是把“hook 回调采集数据”和“更新共享状态/生成报告”解耦之后，两者衔接的关键一环——
 * 所有这些处理都发生在同一条后台线程，串行执行，因此 ThreadHolder 内部不需要额外加锁。
 */
void HookLooper::handle(int what, void *data) {
  looper::handle(what, data);
  switch (what) {
    case ACTION_ADD_THREAD: {
      koom::Log::info(looper_tag, "AddThread");
      auto info = static_cast<HookAddInfo *>(data);
      holder->AddThread(info->tid, info->pthread, info->is_thread_detached,
                        info->time, info->create_arg);
      delete info;
      break;
    }
    case ACTION_JOIN_THREAD: {
      koom::Log::info(looper_tag, "JoinThread");
      auto info = static_cast<HookInfo *>(data);
      holder->JoinThread(info->thread_id);
      delete info;
      break;
    }
    case ACTION_DETACH_THREAD: {
      koom::Log::info(looper_tag, "DetachThread");
      auto info = static_cast<HookInfo *>(data);
      holder->DetachThread(info->thread_id);
      delete info;
      break;
    }
    case ACTION_EXIT_THREAD: {
      koom::Log::info(looper_tag, "ExitThread");
      auto info = static_cast<HookExitInfo *>(data);
      holder->ExitThread(info->thread_id, info->threadName, info->time);
      delete info;
      break;
    }
    case ACTION_REFRESH: {
      koom::Log::info(looper_tag, "Refresh");
      auto info = static_cast<SimpleHookInfo *>(data);
      holder->ReportThreadLeak(info->time);
      delete info;
      break;
    }
    default: {
    }
  }
}
/** 把 hook 回调采集到的事件投递到后台队列；实际入队/唤醒逻辑复用基类 looper::post。 */
void HookLooper::post(int what, void *data) { looper::post(what, data); }
}  // namespace koom