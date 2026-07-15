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
 * Created by Qiushi Xue <xueqiushi@kuaishou.com> on 2021.
 *
 */

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <hprof_strip.h>
#include <jni.h>
#include <kwai_linker/kwai_dlfcn.h>
#include <log/log.h>
#include <pthread.h>
#include <unistd.h>
#include <wait.h>

#include <string>

#undef LOG_TAG
#define LOG_TAG "JNIBridge"

using namespace kwai::leak_monitor;

// 本文件是Kotlin侧ForkStripHeapDumper调用native能力的JNI桥接层：
// 先通过initStripDump注册open/write的hook，再通过hprofName告知目标hprof文件名，
// 后续dump过程中写入该hprof文件的数据会被hprof_strip.cpp实时裁剪，减小最终文件体积。
#ifdef __cplusplus
// 使用C链接方式声明，避免C++名字修饰(name mangling)，
// 使符号名与JNI规范要求的Java_包名_类名_方法名完全一致，供JVM按名查找native实现。
extern "C" {
#endif
/**
 * JNI bridge for hprof crop
 */
/**
 * 由Kotlin层在fork出的dump子进程发起heap dump前调用，
 * 用于提前注册libart/libbase等so中open、write符号的hook，
 * 这样后续系统调用hprof写入时才能被HprofStrip拦截并裁剪。
 */
JNIEXPORT void JNICALL
Java_com_kwai_koom_javaoom_hprof_ForkStripHeapDumper_initStripDump(
    JNIEnv *env ATTRIBUTE_UNUSED, jobject jobject ATTRIBUTE_UNUSED) {
  // 触发xhook注册，让后续所有open/write调用都会经过HprofStrip的钩子函数
  HprofStrip::HookInit();
}

/**
 * 将Kotlin层生成的hprof文件名传递给native层，
 * 使HookOpenInternal能在拦截到的open调用中通过文件名匹配出目标hprof的fd，
 * 从而只对该fd的write调用做裁剪，不影响进程内其他文件的读写。
 */
JNIEXPORT void JNICALL
Java_com_kwai_koom_javaoom_hprof_ForkStripHeapDumper_hprofName(
    JNIEnv *env, jobject jobject ATTRIBUTE_UNUSED, jstring name) {
  // 跨越Java/native边界：将JVM管理的jstring拷贝为native可直接使用的C字符串
  const char *hprofName = env->GetStringUTFChars(name, nullptr);
  HprofStrip::GetInstance().SetHprofName(hprofName);
  // 与GetStringUTFChars配对释放，避免JVM侧字符串被长期固定(pin)而无法被GC移动/回收
  env->ReleaseStringUTFChars(name, hprofName);
}

#ifdef __cplusplus
}
#endif
