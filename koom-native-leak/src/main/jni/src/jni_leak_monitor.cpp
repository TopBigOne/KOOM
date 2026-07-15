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

// JNI bridge between the Kotlin/Java LeakMonitor API and the native
// hook->record->scan->match pipeline (LeakMonitor in leak_monitor.cpp). Also
// owns symbolication of leak call stacks: it uses MemoryMap to resolve raw
// return addresses captured during the "record" stage into .so + offset (or
// human-readable symbol) pairs before handing results back to Java.
// 中文：本文件是 Kotlin/Java 端 LeakMonitor API 与 native 端
// hook->record->scan->match 流水线（即 leak_monitor.cpp 中的 LeakMonitor）
// 之间的 JNI 桥接层。同时它还负责泄漏调用栈的符号化：使用 MemoryMap 把
// “record”阶段捕获的原始返回地址解析成 .so + 偏移（或可读符号名）对，
// 再把结果交还给 Java 层。
#define LOG_TAG "jni_leak_monitor"
#include <jni.h>
#include <jni_util/scoped_local_ref.h>
#include <libgen.h>
#include <log/kcheck.h>
#include <log/log.h>

#include <cstdlib>
#include <vector>

#include "android/log.h"
#include "leak_monitor.h"
#include "memory_map.h"

namespace kwai {
namespace leak_monitor {
// Looks up a Java class by name via JNI and aborts (LOG_FATAL_IF) if it is
// missing, since a missing class means the Kotlin/Java side and native side
// have drifted apart and nothing downstream can work correctly.
// 中文：通过 JNI 按名称查找 Java 类，如果找不到就直接终止（LOG_FATAL_IF），
// 因为类找不到意味着 Kotlin/Java 端与 native 端已经不一致了，后续任何操作
// 都无法正常工作。
#define FIND_CLASS(var, class_name)                      \
  do {                                                   \
    var = env->FindClass(class_name);                    \
    LOG_FATAL_IF(!var, "FindClass %s fail", class_name); \
  } while (0)

// Looks up a Java method ID via JNI, aborting on failure for the same reason
// as FIND_CLASS above.
// 中文：通过 JNI 查找 Java 方法 ID，失败时终止的原因与上面的 FIND_CLASS
// 相同。
#define GET_METHOD_ID(var, clazz, name, descriptor)  \
  do {                                               \
    var = env->GetMethodID(clazz, name, descriptor); \
    LOG_FATAL_IF(!var, "GetMethodID %s fail", name); \
  } while (0)

struct ClassInfo {
  jclass global_ref;
  jmethodID construct_method;
  ClassInfo() : global_ref(nullptr), construct_method(nullptr) {}
};

static ClassInfo g_leak_record;
static ClassInfo g_frame_info;

static const char *kLeakMonitorFullyName =
    "com/kwai/koom/nativeoom/leakmonitor/LeakMonitor";
static const char *kLeakRecordFullyName =
    "com/kwai/koom/nativeoom/leakmonitor/LeakRecord";
static const char *kFrameInfoFullyName =
    "com/kwai/koom/nativeoom/leakmonitor/FrameInfo";
static const uint32_t kNumDropFrame = 2;
static MemoryMap g_memory_map;
static bool g_enable_local_symbolic = false;

/**
 * Releases the cached global references to the LeakRecord/FrameInfo Java
 * classes, used both on clean uninstall and on partial-initialization
 * failure during InstallMonitor.
 *
 * 中文：释放缓存的 LeakRecord/FrameInfo Java 类的全局引用；无论是正常
 * 卸载，还是 InstallMonitor 过程中初始化到一半失败，都会调用这里。
 */
static void Clean(JNIEnv *env) {
  if (g_leak_record.global_ref) {
    env->DeleteGlobalRef(g_leak_record.global_ref);
    memset(&g_leak_record, 0, sizeof(g_leak_record));
  }
  if (g_frame_info.global_ref) {
    env->DeleteGlobalRef(g_frame_info.global_ref);
    memset(&g_frame_info, 0, sizeof(g_frame_info));
  }
}

/**
 * Helper used while setting up JNI class/method caches: if `value` is falsy
 * (a lookup failed), tears down whatever global refs were already acquired
 * via Clean() so InstallMonitor never leaks partially-initialized state.
 *
 * 中文：在建立 JNI 类/方法缓存的过程中使用的辅助函数：如果 `value`
 * 为假（说明查找失败），就通过 Clean() 清理掉已经获取到的全局引用，
 * 以保证 InstallMonitor 不会遗留下一份只初始化了一半的状态。
 */
template <typename T>
static inline bool CheckedClean(JNIEnv *env, T value) {
  if (value) {
    return true;
  }
  Clean(env);
  return false;
}

/** JNI-exposed nativeUninstallMonitor: tears down the whole native pipeline
 * — removes the malloc/free hooks, clears symbolication state, and releases
 * cached JNI global refs.
 *
 * 中文：JNI 暴露的 nativeUninstallMonitor：拆除整个 native 流水线——移除
 * malloc/free 的 hook，清空符号化相关的状态，并释放缓存的 JNI 全局引用。
 */
static void UninstallMonitor(JNIEnv *env, jclass) {
  LeakMonitor::GetInstance().Uninstall();
  g_memory_map.~MemoryMap();
  Clean(env);
}

/**
 * JNI-exposed nativeInstallMonitor: caches the LeakRecord/FrameInfo Java
 * class + constructor handles (so later per-leak object construction avoids
 * repeated JNI lookups), converts the selected/ignore .so name arrays from
 * Java to native vectors, and finally installs the malloc-family hooks via
 * LeakMonitor::Install — starting the "hook" stage of the pipeline.
 *
 * 中文：JNI 暴露的 nativeInstallMonitor：缓存 LeakRecord/FrameInfo 的 Java
 * 类及构造方法句柄（这样后续每次构造泄漏对象时都无需再重复做 JNI 查找），
 * 把选中/忽略的 .so 名称数组从 Java 端转换成 native 端的 vector，最后通过
 * LeakMonitor::Install 安装 malloc 系列 hook——即启动流水线的“hook”阶段。
 */
static bool InstallMonitor(JNIEnv *env, jclass clz, jobjectArray selected_array,
                           jobjectArray ignore_array,
                           jboolean enable_local_symbolic) {
  jclass leak_record;
  FIND_CLASS(leak_record, kLeakRecordFullyName);
  g_leak_record.global_ref =
      reinterpret_cast<jclass>(env->NewGlobalRef(leak_record));
  if (!CheckedClean(env, g_leak_record.global_ref)) {
    return false;
  }
  GET_METHOD_ID(g_leak_record.construct_method, leak_record, "<init>",
                "(JILjava/lang/String;[Lcom/kwai/koom/nativeoom/leakmonitor/"
                "FrameInfo;)V");

  jclass frame_info;
  FIND_CLASS(frame_info, kFrameInfoFullyName);
  g_frame_info.global_ref =
      reinterpret_cast<jclass>(env->NewGlobalRef(frame_info));
  if (!CheckedClean(env, g_frame_info.global_ref)) {
    return false;
  }
  GET_METHOD_ID(g_frame_info.construct_method, frame_info, "<init>",
                "(JLjava/lang/String;)V");

  g_enable_local_symbolic = enable_local_symbolic;

  auto array_to_vector =
      [](JNIEnv *env, jobjectArray jobject_array) -> std::vector<std::string> {
    std::vector<std::string> ret;
    int length = env->GetArrayLength(jobject_array);

    if (length <= 0) {
      return ret;
    }

    for (jsize i = 0; i < length; i++) {
      auto str = reinterpret_cast<jstring>(
          env->GetObjectArrayElement(jobject_array, i));
      const char *data = env->GetStringUTFChars(str, nullptr);
      ret.emplace_back(data);
      env->ReleaseStringUTFChars(str, data);
    }

    return std::move(ret);
  };

  std::vector<std::string> selected_so = array_to_vector(env, selected_array);
  std::vector<std::string> ignore_so = array_to_vector(env, ignore_array);
  return CheckedClean(
      env, LeakMonitor::GetInstance().Install(&selected_so, &ignore_so));
}

/**
 * JNI-exposed nativeSetMonitorThreshold: forwards the minimum tracked
 * allocation size to LeakMonitor, clamped to at least the built-in default
 * so callers can't disable the size filter entirely.
 *
 * 中文：JNI 暴露的 nativeSetMonitorThreshold：把最小跟踪分配大小转发给
 * LeakMonitor，并限制不能低于内置默认值，防止调用方彻底关闭大小过滤。
 */
static void SetMonitorThreshold(JNIEnv *, jclass, jint size) {
  if (size < kDefaultAllocThreshold) {
    size = kDefaultAllocThreshold;
  }
  LeakMonitor::GetInstance().SetMonitorThreshold(size);
}

/** JNI-exposed nativeGetAllocIndex: returns the current allocation counter.
 *
 * 中文：JNI 暴露的 nativeGetAllocIndex：返回当前的分配计数器。
 */
static jlong GetAllocIndex(JNIEnv *, jclass) {
  return LeakMonitor::GetInstance().CurrentAllocIndex();
}

/**
 * Converts a resolved native call stack (offset + symbol/so-name pairs) into
 * a Java array of FrameInfo objects for delivery back to Kotlin/Java.
 *
 * 中文：把已解析好的 native 调用栈（偏移量 + 符号名/so 名称对）转换成一个
 * Java 端 FrameInfo 对象数组，交还给 Kotlin/Java。
 */
static jobjectArray BuildFrames(
    JNIEnv *env, std::vector<std::pair<jlong, std::string>> &frames) {
  jsize index = 0;
  jobjectArray frame_array =
      env->NewObjectArray(frames.size(), g_frame_info.global_ref, nullptr);
  for (auto &frame : frames) {
    ScopedLocalRef<jstring> so_name(env,
                                    env->NewStringUTF(frame.second.c_str()));
    ScopedLocalRef<jobject> frame_info(
        env,
        env->NewObject(g_frame_info.global_ref, g_frame_info.construct_method,
                       frame.first, so_name.get()));
    env->SetObjectArrayElement(frame_array, index++, frame_info.get());
  }
  return frame_array;
}

/**
 * Constructs a single Java LeakRecord object (index, size, allocating thread
 * name, symbolicated stack frames) to represent one confirmed leak.
 *
 * 中文：构造一个 Java 端的 LeakRecord 对象（序号、大小、分配线程名、
 * 已符号化的调用栈帧），用来表示一次确认的泄漏。
 */
static jobject BuildLeakRecord(JNIEnv *env, uint64_t index, uint32_t size,
                               char *thread_name, jobjectArray frames) {
  ScopedLocalRef<jstring> name(env, env->NewStringUTF(thread_name));
  return env->NewObject(g_leak_record.global_ref,
                        g_leak_record.construct_method, index, size, name.get(),
                        frames);
}

/**
 * JNI-exposed nativeGetLeakAllocs: the final "report" step of the pipeline.
 * Pulls the leaked AllocRecords produced by LeakMonitor::GetLeakAllocs()
 * (which already did the scan+match work), symbolizes each raw backtrace
 * address via MemoryMap (turning PCs into .so+offset or human-readable
 * symbol names), and populates the caller-supplied Java Map keyed by the
 * (confused) address string with constructed LeakRecord objects.
 *
 * 中文：JNI 暴露的 nativeGetLeakAllocs：流水线的最后一步“上报”。取出
 * LeakMonitor::GetLeakAllocs() 已经完成 scan+match 工作后产出的泄漏
 * AllocRecord 列表，通过 MemoryMap 把每一个原始调用栈地址符号化（把 PC 转成
 * .so+偏移或可读的符号名），并以（混淆后的）地址字符串为键，把构造好的
 * LeakRecord 对象填充进调用方传入的 Java Map。
 */
static void GetLeakAllocs(JNIEnv *env, jclass, jobject leak_record_map) {
  ScopedLocalRef<jclass> map_class(env, env->GetObjectClass(leak_record_map));
  jmethodID put_method;
  GET_METHOD_ID(put_method, map_class.get(), "put",
                "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
  std::vector<std::shared_ptr<AllocRecord>> leak_allocs =
      LeakMonitor::GetInstance().GetLeakAllocs();

  for (auto &leak_alloc : leak_allocs) {
    if (leak_alloc->num_backtraces <= kNumDropFrame) {
      continue;
    }

    leak_alloc->num_backtraces -= kNumDropFrame;
    std::vector<std::pair<jlong, std::string>> frames;
    for (int i = 0; i < leak_alloc->num_backtraces; i++) {
      uintptr_t offset;
      // Maps each raw return-address PC captured during the "record" stage
      // (frame-pointer unwind, see stack_trace.cpp) to the /proc/self/maps
      // entry (.so) it falls into, plus its offset within that library.
      // 中文：把“record”阶段（帧指针回溯，见 stack_trace.cpp）捕获到的每一个
      // 原始返回地址 PC，映射到它所落入的 /proc/self/maps 条目（即某个
      // .so），并算出它在该库内的偏移量。
      auto *map_entry = g_memory_map.CalculateRelPc(
          leak_alloc->backtrace[i + kNumDropFrame], &offset);

      if (!map_entry) {
        continue;
      }

      if (map_entry->NeedIgnore()) {
        leak_alloc->num_backtraces = i;
        break;
      }

      std::string symbol_info =
          g_enable_local_symbolic
              ? g_memory_map.FormatSymbol(
                    map_entry, leak_alloc->backtrace[i + kNumDropFrame])
              : basename(map_entry->name.c_str());
      frames.emplace_back(static_cast<jlong>(offset), symbol_info);
    }

    if (!leak_alloc->num_backtraces || frames.empty()) {
      continue;
    }

    // leak_alloc->address is stored obfuscated (CONFUSE == bitwise NOT, see
    // leak_monitor.h); revert it before formatting the human-readable key.
    // 中文：leak_alloc->address 存储时是经过混淆的（CONFUSE 即按位取反，
    // 见 leak_monitor.h），格式化成可读的键之前需要先把它还原。
    char address[sizeof(uintptr_t) * 2 + 1];
    snprintf(address, sizeof(uintptr_t) * 2 + 1, "%lx",
             CONFUSE(leak_alloc->address));
    ScopedLocalRef<jstring> memory_address(env, env->NewStringUTF(address));
    ScopedLocalRef<jobjectArray> frames_ref(env, BuildFrames(env, frames));
    ScopedLocalRef<jobject> leak_record_ref(
        env, BuildLeakRecord(env, leak_alloc->index, leak_alloc->size,
                             leak_alloc->thread_name, frames_ref.get()));
    ScopedLocalRef<jobject> no_use(
        env,
        env->CallObjectMethod(leak_record_map, put_method, memory_address.get(),
                              leak_record_ref.get()));
  }
}

static const JNINativeMethod kLeakMonitorMethods[] = {
    {"nativeInstallMonitor", "([Ljava/lang/String;[Ljava/lang/String;Z)Z",
     reinterpret_cast<void *>(InstallMonitor)},
    {"nativeUninstallMonitor", "()V",
     reinterpret_cast<void *>(UninstallMonitor)},
    {"nativeSetMonitorThreshold", "(I)V",
     reinterpret_cast<void *>(SetMonitorThreshold)},
    {"nativeGetAllocIndex", "()J", reinterpret_cast<void *>(GetAllocIndex)},
    {"nativeGetLeakAllocs", "(Ljava/util/Map;)V",
     reinterpret_cast<void *>(GetLeakAllocs)}};

/**
 * Standard JNI library entry point: registers the native method table above
 * against the Kotlin/Java LeakMonitor class so nativeInstallMonitor/
 * nativeUninstallMonitor/etc. can be called from Java.
 *
 * 中文：标准的 JNI 库入口函数：把上面的 native 方法表注册到 Kotlin/Java 端
 * 的 LeakMonitor 类上，使 nativeInstallMonitor/nativeUninstallMonitor 等
 * 方法可以从 Java 层被调用。
 */
extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
  JNIEnv *env;

  if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_4) != JNI_OK) {
    ALOGE("GetEnv Fail!");
    return JNI_ERR;
  }

  jclass leak_monitor;
  FIND_CLASS(leak_monitor, kLeakMonitorFullyName);
#define NELEM(x) (sizeof(x) / sizeof((x)[0]))
  if (env->RegisterNatives(leak_monitor, kLeakMonitorMethods,
                           NELEM(kLeakMonitorMethods)) != JNI_OK) {
    ALOGE("RegisterNatives Fail!");
    return JNI_ERR;
  }

  return JNI_VERSION_1_4;
}
}  // namespace leak_monitor
}  // namespace kwai
