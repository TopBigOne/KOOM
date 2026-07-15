/*
 * Copyright (c) 2020. Kwai, Inc. All rights reserved.
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
 * Created by Qiushi Xue <xueqiushi@kuaishou.com> on 2020.
 *
 */

#include <cstdint>
#include <ctime>
#include <kwai_util/ktime.h>
#include <kwai_util/kwai_macros.h>

static constexpr uint64_t MILLIS_PER_SEC = 1000;
static constexpr uint64_t MICRO_PER_SEC = 1000 * MILLIS_PER_SEC;
static constexpr uint64_t NANOS_PER_SEC = 1000 * MICRO_PER_SEC;

/**
 * Nanosecond-resolution timestamp intended for measuring elapsed durations/intervals
 * (e.g. "how long did this dump take"), not wall-clock time.
 *
 * 中文：纳秒精度的时间戳，用于测量耗时/时间间隔（例如"这次转储耗时多久"），
 * 而不是用来表示挂钟时间。
 */
KWAI_EXPORT uint64_t nanotime() {
  timespec ts{};
  // CLOCK_MONOTONIC is deliberately used instead of CLOCK_REALTIME here: it only ever
  // moves forward at a steady rate and is immune to wall-clock adjustments (NTP sync,
  // user changing the date/time, timezone changes). Using CLOCK_REALTIME for interval
  // measurement could make a duration appear negative or wildly wrong if the system
  // clock jumps backwards mid-measurement.
  // 中文：这里特意使用 CLOCK_MONOTONIC 而不是 CLOCK_REALTIME：它只会以恒定速率
  // 单调向前推进，不受挂钟时间调整的影响（NTP 同步、用户修改日期/时间、时区变更
  // 等）。如果用 CLOCK_REALTIME 来测量时间间隔，一旦系统时钟在测量过程中往回跳变，
  // 就可能导致算出的时长为负数或严重失真。
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec * NANOS_PER_SEC + ts.tv_nsec);
}

/**
 * Millisecond-resolution UTC wall-clock timestamp, for when callers need an actual
 * point-in-time value (e.g. to display or persist alongside a log entry) rather than
 * a duration - unlike nanotime() above, this is expected to be able to jump if the
 * system clock is adjusted, which is fine for its use case.
 *
 * 中文：毫秒精度的 UTC 挂钟时间戳，用于调用方需要一个真实的时间点（例如与日志
 * 条目一起展示或持久化）而非一个时长的场景——与上面的 nanotime() 不同，这个值
 * 允许在系统时钟被调整时发生跳变，这对它的使用场景来说是可以接受的。
 */
uint64_t now() {
  timespec ts{};
  // CLOCK_REALTIME here (vs nanotime()'s CLOCK_MONOTONIC) is intentional: this
  // function's contract is "current UTC time", which requires wall-clock semantics.
  // 中文：这里使用 CLOCK_REALTIME（相对于 nanotime() 的 CLOCK_MONOTONIC）是特意
  // 为之：这个函数的约定语义是"当前 UTC 时间"，这就要求具备挂钟时间的语义。
  clock_gettime(CLOCK_REALTIME, &ts);
  return static_cast<uint64_t>(ts.tv_sec * MILLIS_PER_SEC +
                               ts.tv_nsec * MILLIS_PER_SEC / NANOS_PER_SEC);
}