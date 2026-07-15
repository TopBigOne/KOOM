/*
 * Copyright (c) 2025. Kwai, Inc. All rights reserved.
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
 * Created by wangzefeng <wangzefeng@kuaishou.com> on 2025.
 *
 */

#ifndef KOOM_DEFINES_H_
#define KOOM_DEFINES_H_

// Android 15 对应的 API Level，用于 HprofDumpImpl::GetInstance 在运行时
// 判断走哪一套挂起/fork/dump 实现（below R / below V / V 及以上）。
#define __ANDROID_API_V__ 35

namespace kwai {
namespace leak_monitor {

// What caused the GC?
// 这两个枚举的取值需要和目标设备上 ART 内部真实的 art::gc::GcCause /
// art::gc::CollectorType 枚举值保持一致，因为它们会被原样传给
// dlsym 出来的 ART 内部函数（ScopedGCCriticalSection 构造函数）。
// 由于只是用来“占位”阻止 GC 在挂起期间运行，取值是否恰好等于 ART 里
// 语义正确的那个枚举成员并不重要，只要是一个合法的枚举值即可。
enum GcCause {
  // Not a real GC cause, used to prevent hprof running in the middle of GC.
  kGcCauseHprof = 15,
};

// Which types of collections are able to be performed.
enum CollectorType {
  // Hprof fake collector.
  // NOTE: Use any fake collector is ok
  //  on AOSP Android 15, kCollectorTypeHprof = 15,
  //  but on AOSP older sys version, kCollectorTypeHprof maybe 14 / 13 /...
  kCollectorTypeHprof = 15,
};

} // namespace leak_monitor
} // namespace kwai

#endif //KOOM_DEFINES_H_
