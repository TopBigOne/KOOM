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

#ifndef APM_LOG_H
#define APM_LOG_H

#include <android/log.h>
#include <stdio.h>

namespace koom {

// 对 Android NDK 日志 API（__android_log_print）的轻量封装，供本模块各处打印调试信息，
// 受 log_enable 开关控制，默认关闭以避免在生产环境产生额外开销和 logcat 噪音。
class Log {
 public:
  enum Type { Info, Error };

  /** 格式化并输出一条 INFO 级别日志到 logcat（受 log_enable 开关控制）。 */
  static void info(const char *tag, const char *format, ...) {
    if (!log_enable) return;
    char log_buffer[kMaxLogLine];
    va_list args;
    va_start(args, format);
    vsnprintf(const_cast<char *>(log_buffer), kMaxLogLine, format, args);
    va_end(args);
    log(Info, tag, log_buffer);
  }

  /** 格式化并输出一条 ERROR 级别日志到 logcat（受 log_enable 开关控制）。 */
  static void error(const char *tag, const char *format, ...) {
    if (!log_enable) return;
    char log_buffer[kMaxLogLine];
    va_list args;
    va_start(args, format);
    vsnprintf(const_cast<char *>(log_buffer), kMaxLogLine, format, args);
    va_end(args);
    log(Error, tag, log_buffer);
  }

  static bool log_enable;

 private:
  /** 实际调用 Android NDK 的 __android_log_print 把已格式化好的字符串写入 logcat。 */
  static void log(Type type, const char *tag, char *log_buffer) {
    if (!log_enable) return;
    __android_log_print(type == Info ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                        tag, "%s", log_buffer);
  }

  static const int kMaxLogLine = 512;
};
}  // namespace koom

#endif  // APM_LOG_H
