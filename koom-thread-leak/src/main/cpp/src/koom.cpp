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

#include "koom.h"

#include <jni.h>

#include "common/callstack.h"
#include "common/util.h"
#include "thread/hook_looper.h"
#include "thread/thread_hook.h"

namespace koom {

int Util::android_api;
bool Log::log_enable = false;

JavaVM *java_vm_;
jclass native_handler_class;
jmethodID java_callback_method;
// 是否正在运行/hook 是否生效的全局开关；ThreadHooker::hookEnabled() 直接读取它，
// pthread_create/join/detach/exit 的 hook 函数在它为 false 时会直接透传给真正的 libc 实现。
std::atomic<bool> isRunning;
// 后台工作线程（生产者-消费者模型），所有 hook 回调只投递事件到这里，
// 真正修改 ThreadHolder 状态、生成上报 JSON 的工作都在这个专用线程完成，避免拖慢 hook 调用点。
HookLooper *sHookLooper;
// 线程退出后，超过多久仍未 join/detach 才判定为“泄漏”并上报（毫秒），由 Java 层可配置。
long threadLeakDelay;

/**
 * 模块初始化入口，由 JNI_OnLoad 调用。
 * 缓存 JavaVM、查找 Java 层 NativeHandler.nativeReport 方法 ID（供后续上报回调 JavaCallback 使用），
 * 并完成 Util（Android API level）和 CallStack（符号化/unwinder）等基础设施的初始化。
 */
void Init(JavaVM *vm, _JNIEnv *env) {
  java_vm_ = vm;
  auto clazz = env->FindClass(
      "com/kwai/performance/overhead/thread/monitor/NativeHandler");
  native_handler_class = static_cast<jclass>(env->NewGlobalRef(clazz));
  java_callback_method = env->GetStaticMethodID(
      native_handler_class, "nativeReport", "(Ljava/lang/String;)V");
  Util::Init();
  Log::info("koom", "Init, android api:%d", Util::AndroidApi());
  CallStack::Init();
}

/**
 * 启动线程泄漏检测：创建（或重建）后台 HookLooper 工作线程，
 * 再调用 ThreadHooker::Start() 对已加载/后续加载的 so 做 pthread_create/exit/join/detach 的 PLT hook，
 * 最后置位 isRunning，使 hook 回调开始真正生效。
 */
void Start() {
  if (isRunning) {
    return;
  }
  // 初始化数据
  delete sHookLooper;
  sHookLooper = new HookLooper();
  koom::ThreadHooker::Start();
  isRunning = true;
}

/**
 * 停止检测：先关闭 isRunning 使 hook 回调不再记录新事件，
 * 再让后台 looper 退出（等待其消费完队列中剩余消息后结束工作线程）。
 */
void Stop() {
  isRunning = false;
  koom::ThreadHooker::Stop();
  sHookLooper->quit();
}

/**
 * 触发一次异步的泄漏扫描：把当前时间戳封装成 SimpleHookInfo，
 * 投递 ACTION_REFRESH 消息到后台 looper，由其在工作线程上执行 ThreadHolder::ReportThreadLeak。
 */
void Refresh() {
  auto info = new SimpleHookInfo(Util::CurrentTimeNs());
  sHookLooper->post(ACTION_REFRESH, info);
}

/**
 * 获取当前线程可用的 JNIEnv。由于 pthread hook 可能在 JVM 未附加的 native 线程上触发，
 * 若检测到当前线程未 attach（JNI_EDETACHED）且 doAttach 为 true，则调用 AttachCurrentThread 挂载，
 * 这样才能安全地调用 Java 方法（如上报回调）。
 */
JNIEnv *GetEnv(bool doAttach) {
  JNIEnv *env = nullptr;
  int status = java_vm_->GetEnv((void **)&env, JNI_VERSION_1_6);
  if ((status == JNI_EDETACHED || env == nullptr) && doAttach) {
    status = java_vm_->AttachCurrentThread(&env, nullptr);
    if (status < 0) {
      env = nullptr;
    }
  }
  return env;
}

/**
 * 把泄漏检测结果（JSON 字符串）通过 JNI 回调传回 Java 层的 NativeHandler.nativeReport()，
 * 是整个 hook->跟踪->上报流水线的最后一环。
 */
void JavaCallback(const char *value, bool doAttach) {
  JNIEnv *env = GetEnv(doAttach);
  if (env != nullptr && value != nullptr) {
    Log::error("koom", "JavaCallback %d", strlen(value));
    jstring string_value = env->NewStringUTF(value);
    env->CallStaticVoidMethod(native_handler_class, java_callback_method,
                              string_value);
    Log::info("koom", "JavaCallback finished");
  } else {
    Log::info("koom", "JavaCallback fail no JNIEnv");
  }
}

}  // namespace koom