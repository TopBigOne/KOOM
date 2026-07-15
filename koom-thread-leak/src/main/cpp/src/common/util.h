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

#ifndef APM_UTIL_H
#define APM_UTIL_H

#include <dirent.h>
#include <jni.h>

#include <fstream>
#include <map>
#include <set>
#include <streambuf>
#include <string>
#include <vector>

#include "log.h"

namespace koom {

// 与 Android 版本、时间戳、字符串处理相关的通用小工具集合，被 callstack/thread_hook/thread_holder 等多处复用。
class Util {
 public:
  static int android_api;

  /** 缓存当前设备的 Android API level，避免重复调用系统接口；在 koom::Init 中调用一次。 */
  static void Init() { android_api = android_get_device_api_level(); }

  static int AndroidApi() { return android_api; }

  /** 获取单调时钟的 timespec，不受系统时间被用户调整影响，适合做耗时统计。 */
  static timespec CurrentClockTime() {
    struct timespec now_time {};
    clock_gettime(CLOCK_MONOTONIC, &now_time);
    return now_time;
  }

  /**
   * 获取单调递增的纳秒级时间戳（CLOCK_MONOTONIC），用于记录线程创建/退出/join/detach 各事件的时间，
   * 以及计算“线程退出后经过多久仍未被回收”从而判定泄漏。
   */
  static long long CurrentTimeNs() {
    struct timespec now_time {};
    clock_gettime(CLOCK_MONOTONIC, &now_time);
    return now_time.tv_sec * 1000000000LL + now_time.tv_nsec;
  }

  /** 按分隔符切分字符串，用于把多行 Java 堆栈文本拆成逐行列表以便重新拼接格式化。 */
  static std::vector<std::string> Split(const std::string &s, char seperator) {
    std::vector<std::string> output;
    std::string::size_type prev_pos = 0, pos = 0;

    while ((pos = s.find(seperator, pos)) != std::string::npos) {
      std::string substring(s.substr(prev_pos, pos - prev_pos));
      output.push_back(substring);
      prev_pos = ++pos;
    }

    output.push_back(s.substr(prev_pos, pos - prev_pos));  // Last word

    return output;
  }
};
}  // namespace koom
#endif  // APM_UTIL_H
