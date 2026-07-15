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

#ifndef APM_KOOM_H
#define APM_KOOM_H

#include <jni.h>

#include "thread/hook_looper.h"

namespace koom {

extern JavaVM *java_vm_;

extern jclass native_handler_class;

extern jmethodID java_callback_method;

// 后台生产者-消费者工作线程，承载 pthread hook 事件的串行化处理与泄漏上报。
extern HookLooper *sHookLooper;

// 模块是否处于运行状态；为 false 时所有 hook 直接透传给原始 pthread_* 实现，不做任何记录。
extern std::atomic<bool> isRunning;

// 线程退出后允许未 join/detach 存在的宽限时间（毫秒），超过此时长仍未回收才判定为泄漏。
extern int64_t threadLeakDelay;

/** 初始化：缓存 JavaVM、查找 Java 层回调方法、初始化 Util/CallStack 基础设施。 */
extern void Init(JavaVM *vm, JNIEnv *p_env);

/** 启动检测：创建后台 looper 并对 pthread_create/exit/join/detach 完成 PLT hook。 */
extern void Start();

/** 停止检测：关闭 hook 开关并让后台 looper 退出。 */
extern void Stop();

extern void Report(JNIEnv *env, jobject obj, jstring type);

/** 触发一次异步的“已退出未回收线程”扫描与上报。 */
extern void Refresh();

/** 获取（必要时 attach）当前线程的 JNIEnv，供 native 线程上安全调用 Java 方法。 */
JNIEnv *GetEnv(bool doAttach = true);

/** 把泄漏检测结果 JSON 通过 JNI 回调给 Java 层 NativeHandler.nativeReport()。 */
void JavaCallback(const char *value, bool doAttach = true);
}  // namespace koom

#endif  // APM_KOOM_H
