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

// Wraps the xhook PLT/GOT-hooking engine to implement the "hook" stage of
// the pipeline. Instead of patching the target .so's code section, xhook
// rewrites entries in each target .so's Global Offset Table (GOT) so that
// calls through the PLT to malloc/free/etc are redirected to our monitor
// wrapper functions (leak_monitor.cpp's mallocMonitor/freeMonitor/...); the
// real libc functions are then called explicitly from inside those wrappers.
// 中文：本文件封装 xhook 这个 PLT/GOT hook 引擎，用来实现流水线的“hook”
// 阶段。xhook 并不修改目标 .so 的代码段，而是重写每个目标 .so 全局偏移表
// （GOT）中的条目，使得通过 PLT 对 malloc/free 等函数的调用被重定向到我们
// 的监控包装函数（即 leak_monitor.cpp 中的 mallocMonitor/freeMonitor/...）；
// 真正的 libc 函数随后再由这些包装函数内部显式调用。
#define LOG_TAG "hook_helper"
#include "utils/hook_helper.h"

#include <dlopencb.h>
#include <log/log.h>
#include <xhook.h>

std::vector<const std::string> HookHelper::register_pattern_;
std::vector<const std::string> HookHelper::ignore_pattern_;
std::vector<std::pair<const std::string, void *const>> HookHelper::methods_;

/**
 * Records which .so's/symbols to hook (and which to leave alone) and
 * performs the first hook pass. Also registers a dlopen callback so that
 * .so's loaded *after* this call (dynamically loaded plugins, etc.) get the
 * same hooks retroactively applied, not just libraries already loaded now.
 *
 * 中文：记录需要 hook 的 .so/符号（以及应当忽略的部分），并执行第一次
 * hook。同时注册一个 dlopen 回调，使得在本次调用*之后*才被加载的 .so
 * （比如动态加载的插件等）也能被追溯性地应用同样的 hook，而不仅仅是当前
 * 已经加载的库。
 */
bool HookHelper::HookMethods(
    std::vector<const std::string> &register_pattern,
    std::vector<const std::string> &ignore_pattern,
    std::vector<std::pair<const std::string, void *const>> &methods) {
  if (register_pattern.empty() || methods.empty()) {
    ALOGE("Hook nothing");
    return false;
  }

  register_pattern_ = std::move(register_pattern);
  ignore_pattern_ = std::move(ignore_pattern);
  methods_ = std::move(methods);
  DlopenCb::GetInstance().AddCallback(Callback);
  return HookImpl();
}

/**
 * Reverses HookMethods(): stops reacting to future dlopen events and clears
 * the stored patterns/method table. Note this does not itself restore
 * previously-hooked GOT entries; LeakMonitor::Uninstall relies on xhook's own
 * teardown via a subsequent hook pass with an empty method set.
 *
 * 中文：撤销 HookMethods() 的效果：不再响应后续的 dlopen 事件，并清空已
 * 存储的模式/方法表。注意这个函数本身并不会恢复之前已经被 hook 过的 GOT
 * 条目；LeakMonitor::Uninstall 依赖的是 xhook 自身的清理机制，通过之后
 * 用一个空的方法集合再执行一次 hook 流程来完成。
 */
void HookHelper::UnHookMethods() {
  DlopenCb::GetInstance().RemoveCallback(Callback);
  register_pattern_.clear();
  ignore_pattern_.clear();
  methods_.clear();
}

/**
 * Invoked whenever a new .so is dlopen'd elsewhere in the process; re-runs
 * the hook pass so the newly mapped library's GOT also gets rewritten to
 * route through our monitor wrappers, since xhook can only patch libraries
 * that are already mapped at the time it runs.
 *
 * 中文：每当进程中其他地方 dlopen 了一个新的 .so 时都会调用这里，重新
 * 执行一遍 hook 流程，使新映射进来的库的 GOT 也被改写为路由到我们的监控
 * 包装函数，因为 xhook 只能修补它运行时已经映射好的库。
 */
void HookHelper::Callback(std::set<std::string> &, int, std::string &) {
  HookImpl();
}

/**
 * Performs one full xhook (re)registration pass under the shared dlopen-
 * callback mutex: clears any previous hook state, registers each
 * (pattern, symbol, replacement) triple, marks ignored .so's so they're
 * skipped, then commits the changes with xhook_refresh. This is what
 * actually rewrites GOT entries in matching .so's to point malloc/free/etc
 * at leak_monitor.cpp's wrapper functions instead of the real libc
 * implementations, without touching the target .so's code section at all.
 *
 * 中文：在共享的 dlopen 回调互斥锁保护下，执行一次完整的 xhook（重新）
 * 注册流程：清除之前的 hook 状态，逐一注册每个 (匹配模式, 符号,
 * 替换函数) 三元组，把需要忽略的 .so 标记为跳过，最后通过 xhook_refresh
 * 提交这些变更。真正把匹配到的 .so 中 malloc/free 等的 GOT 条目改写为
 * 指向 leak_monitor.cpp 中的包装函数（而不是真正的 libc 实现），且完全不
 * 触碰目标 .so 代码段的，就是这一步。
 */
bool HookHelper::HookImpl() {
  pthread_mutex_lock(&DlopenCb::hook_mutex);
  xhook_clear();
  for (auto &pattern : register_pattern_) {
    for (auto &method : methods_) {
      // xhook_register queues a GOT-rewrite rule: for every loaded .so whose
      // path matches `pattern`, redirect its import of symbol
      // method.first (e.g. "malloc") to point at method.second (our wrapper)
      // instead of the real libc implementation.
      // 中文：xhook_register 只是把一条 GOT 重写规则加入队列：对于路径
      // 匹配 `pattern` 的每一个已加载 .so，把它对符号 method.first（例如
      // "malloc"）的导入重定向到 method.second（我们的包装函数），而不是
      // 真正的 libc 实现。
      if (xhook_register(pattern.c_str(), method.first.c_str(), method.second,
                         nullptr) != EXIT_SUCCESS) {
        ALOGE("xhook_register pattern %s method %s fail", pattern.c_str(),
              method.first.c_str());
        pthread_mutex_unlock(&DlopenCb::hook_mutex);
        return false;
      }
    }
  }

  for (auto &pattern : ignore_pattern_) {
    for (auto &method : methods_) {
      // xhook_ignore excludes .so's matching `pattern` from having this
      // symbol hooked at all, e.g. so this monitor's own .so and the xhook
      // engine's .so never end up calling their own wrappers recursively.
      // 中文：xhook_ignore 会把路径匹配 `pattern` 的 .so 完全排除在这个
      // 符号的 hook 范围之外，例如借此保证本监控库自身的 .so 以及 xhook
      // 引擎自身的 .so 永远不会递归地调用它们自己的包装函数。
      if (xhook_ignore(pattern.c_str(), method.first.c_str()) != EXIT_SUCCESS) {
        ALOGE("xhook_ignore pattern %s method %s fail", pattern.c_str(),
              method.first.c_str());
        pthread_mutex_unlock(&DlopenCb::hook_mutex);
        return false;
      }
    }
  }

  // xhook_register/xhook_ignore above only queue rules; xhook_refresh(0)
  // walks the currently loaded .so's and actually performs the GOT
  // rewrites for every queued rule (0 = don't re-hook already-hooked ones).
  // 中文：上面的 xhook_register/xhook_ignore 只是把规则加入队列；
  // xhook_refresh(0) 才会真正遍历当前已加载的 .so，对每一条排队的规则
  // 执行实际的 GOT 重写（参数 0 表示不重复 hook 已经 hook 过的部分）。
  int ret = xhook_refresh(0);
  pthread_mutex_unlock(&DlopenCb::hook_mutex);
  return ret == 0;
}