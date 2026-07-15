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

#ifndef KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_AUTO_TIME_H_
#define KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_AUTO_TIME_H_
#include <log/log.h>

#include <ctime>

/**
 * Simple RAII scope timer: logs how long the enclosing scope took to run
 * (from construction to destruction). Useful for profiling costly steps of
 * the pipeline, e.g. the reachability scan in MemoryAnalyzer, which is
 * explicitly noted as "time consuming".
 *
 * 中文：一个简单的 RAII 作用域计时器：记录所在作用域从构造到析构运行了
 * 多长时间。适合用来分析流水线中开销较大的步骤，例如 MemoryAnalyzer 中
 * 明确标注为“耗时”的可达性扫描。
 */
class AutoTime {
 public:
  /** Starts the timer; `tag` is included in the logged message.
   *
   * 中文：启动计时器；`tag` 会包含在日志信息中。
   */
  AutoTime(const char *tag = nullptr) : tag_(tag), start_(clock()) {}
  /** Logs elapsed CPU time since construction.
   *
   * 中文：记录自构造以来经过的 CPU 时间。
   */
  ~AutoTime() {
    clock_t end = clock();
    ALOGI("%s consume time: %f s", tag_ ? tag_ : "",
          (static_cast<double>(end - start_) / CLOCKS_PER_SEC));
  }

 private:
  const char *tag_;
  clock_t start_;
};
#endif  // KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_AUTO_TIME_H_
