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

#include <jni.h>

#include "common/callstack.h"
#include "koom.h"

// 本文件是 Java/Kotlin 层 NativeHandler 与 C++ 实现之间的 JNI 桥接层，
// 每个 JNI 函数只做参数转换/转发，真正的 hook->跟踪->上报逻辑都在 koom.cpp 和 thread/ 目录下实现。
extern "C" {

/**
 * so 被 System.loadLibrary 加载时由 JVM 自动调用的入口函数。
 * 负责缓存 JavaVM 指针、拿到当前线程的 JNIEnv，并调用 koom::Init 完成
 * CallStack/Util 等基础设施的初始化，为后续的 pthread hook 做准备。
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  koom::Log::info("koom-thread", "JNI_OnLoad");
  JNIEnv *env = nullptr;
  // 获取当前线程关联的 JNIEnv，用于查找 Java 类/方法。
  if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  koom::Init(vm, env);
  return JNI_VERSION_1_6;
}

/**
 * 对应 Java 层 NativeHandler.disableJavaStack()，关闭线程创建时 dump Java 堆栈的功能，
 * 用于在稳定性/性能有风险时降级只保留 native 堆栈。
 */
JNIEXPORT void JNICALL
Java_com_kwai_performance_overhead_thread_monitor_NativeHandler_disableJavaStack(
    JNIEnv *env, jclass jObject) {
  koom::CallStack::DisableJava();
}

/**
 * 对应 Java 层 NativeHandler.disableNativeStack()，关闭线程创建时基于帧指针的 native 堆栈回溯。
 */
JNIEXPORT void JNICALL
Java_com_kwai_performance_overhead_thread_monitor_NativeHandler_disableNativeStack(
    JNIEnv *env, jclass jObject) {
  koom::CallStack::DisableNative();
}

/**
 * 对应 Java 层 NativeHandler.start()，启动整个线程泄漏检测流程：
 * 创建后台 HookLooper 工作线程，并对已加载/后续加载的 so 做 pthread_create/exit/join/detach 的 PLT hook。
 */
JNIEXPORT void JNICALL
Java_com_kwai_performance_overhead_thread_monitor_NativeHandler_start(
    JNIEnv *env, jclass obj) {
  koom::Log::info("koom-thread", "start");
  koom::Start();
}

/**
 * 对应 Java 层 NativeHandler.refresh()，触发一次“泄漏扫描”：
 * 向后台 looper 投递 ACTION_REFRESH 消息，检查已退出但未 join/detach 的线程是否超过延迟阈值，需要上报。
 */
JNIEXPORT void JNICALL
Java_com_kwai_performance_overhead_thread_monitor_NativeHandler_refresh(
    JNIEnv *env, jclass obj) {
  koom::Refresh();
}

/**
 * 对应 Java 层 NativeHandler.stop()，停止检测：标记 hook 禁用并让后台 looper 退出。
 */
JNIEXPORT void JNICALL
Java_com_kwai_performance_overhead_thread_monitor_NativeHandler_stop(
    JNIEnv *env, jclass obj) {
  koom::Stop();
}

/**
 * 对应 Java 层 NativeHandler.setThreadLeakDelay()，设置“线程退出后多久仍未
 * join/detach 才判定为泄漏并上报”的延迟阈值（毫秒），避免正常的短暂延迟 join 被误报。
 */
JNIEXPORT void JNICALL
Java_com_kwai_performance_overhead_thread_monitor_NativeHandler_setThreadLeakDelay(
    JNIEnv *env, jclass thiz, jlong delay) {
  koom::threadLeakDelay = delay;
}

/**
 * 对应 Java 层 NativeHandler.enableNativeLog()，打开 native 层的 logcat 调试日志开关。
 */
JNIEXPORT void JNICALL
Java_com_kwai_performance_overhead_thread_monitor_NativeHandler_enableNativeLog(
    JNIEnv *env, jclass jObject) {
  koom::Log::log_enable = true;
}
}
