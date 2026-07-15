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

#ifndef KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_HOOK_HELPER_H_
#define KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_HOOK_HELPER_H_

#include <mutex>
#include <set>
#include <string>
#include <vector>

/**
 * Static wrapper around the xhook PLT/GOT hooking engine: implements the
 * "hook" stage of the pipeline by rewriting matching .so's Global Offset
 * Table entries for the malloc-family symbols so calls route through
 * leak_monitor.cpp's wrapper functions first, without patching the target
 * .so's code section itself.
 *
 * 中文：对 xhook PLT/GOT hook 引擎的静态封装：通过重写匹配 .so 中 malloc
 * 系列符号在全局偏移表（GOT）中的条目，实现流水线的“hook”阶段，使调用先
 * 路由到 leak_monitor.cpp 的包装函数，而完全不修改目标 .so 自身的代码段。
 */
class HookHelper {
 public:
  /** Registers (pattern, ignore, methods) and performs the first hook pass.
   *
   * 中文：注册（匹配模式、忽略模式、方法列表），并执行第一次 hook。
   */
  static bool HookMethods(
      std::vector<const std::string> &register_pattern,
      std::vector<const std::string> &ignore_pattern,
      std::vector<std::pair<const std::string, void *const>> &methods);
  /** Stops future re-hooking and clears stored hook configuration.
   *
   * 中文：停止后续的重新 hook，并清空已存储的 hook 配置。
   */
  static void UnHookMethods();

 private:
  /** Re-runs the hook pass when a new .so is dlopen'd elsewhere.
   *
   * 中文：当进程中其他地方 dlopen 了一个新的 .so 时，重新执行一遍 hook。
   */
  static void Callback(std::set<std::string> &, int, std::string &);
  /** Performs one xhook register/ignore/refresh pass.
   *
   * 中文：执行一次 xhook 的 register/ignore/refresh 流程。
   */
  static bool HookImpl();
  static std::vector<const std::string> register_pattern_;
  static std::vector<const std::string> ignore_pattern_;
  static std::vector<std::pair<const std::string, void *const>> methods_;
};
#endif  // KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_HOOK_HELPER_H_
