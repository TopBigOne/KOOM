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

#pragma once

#include <cstdint>
#include <sys/cdefs.h>

__BEGIN_DECLS

// Monotonic-clock nanosecond timestamp for measuring elapsed durations/intervals;
// immune to wall-clock adjustments (NTP sync, user changing the date/time), unlike
// now() below. Do not use this to represent an actual point in time.
// 中文：基于单调时钟（monotonic clock）的纳秒级时间戳，用于测量耗时/时间间隔；
// 与下面的 now() 不同，它不受挂钟时间调整（NTP 同步、用户修改日期/时间）的影响。
// 不要用它来表示某个具体的时间点。
uint64_t nanotime();
// UTC time
// Wall-clock millisecond timestamp for representing an actual point in time (e.g. to
// log/display alongside an event); may jump if the system clock is adjusted, unlike
// nanotime() above - use nanotime() instead when measuring how long something took.
// 中文：挂钟毫秒级时间戳，用于表示某个具体的时间点（例如随事件一起记录/展示）；
// 与上面的 nanotime() 不同，它可能会因系统时钟被调整而发生跳变——如果要测量某项
// 操作耗时多久，应改用 nanotime()。
static uint64_t now();

__END_DECLS