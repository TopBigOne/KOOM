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

#include "hprof_dump.h"

#include "hprof_dump_impl.h"

namespace kwai {
namespace leak_monitor {

/**
 * 获取 HprofDump 单例。整个 SDK 中挂起/fork/恢复/dump 的入口都通过这个单例调用，
 * 保证同一进程内不会有两套并发的挂起/fork 流程互相干扰。
 */
HprofDump &HprofDump::GetInstance() {
  static HprofDump hprof_dump;
  return hprof_dump;
}

// android_get_device_api_level()：读取当前设备的 Android API Level，
// 用于在运行时挑选与该系统版本 ART 内部实现相匹配的挂起/fork 策略
// （Android 版本升级后 ART 内部符号、加锁方式经常变化，必须按版本适配）。
HprofDump::HprofDump() : impl_(HprofDumpImpl::GetInstance(android_get_device_api_level())) {}

/**
 * 预先完成一次性初始化：dlopen libart.so 并 dlsym 解析出后续挂起/恢复/dump
 * 所需的 ART 内部符号，避免在真正触发 dump 时才做这些耗时操作。
 */
void HprofDump::Initialize() {
  impl_.Initialize();
}

/**
 * 挂起 ART 虚拟机的所有 Java 线程后立即 fork()，转发给对应版本的实现。
 * 返回值语义与 fork() 一致：0 表示当前处于子进程，>0 表示当前处于父进程
 * 且返回值是子进程 pid，<0 表示挂起或 fork 失败。
 */
pid_t HprofDump::SuspendAndFork() {
  return impl_.SuspendAndFork();
}

/**
 * 恢复父进程中此前被挂起的所有 Java 线程，让宿主 App 尽快继续运行，
 * 不等待子进程 dump 完成即返回。
 */
bool HprofDump::Resume() {
  return impl_.Resume();
}

/**
 * 恢复父进程线程运行的同时，阻塞等待子进程退出，
 * 用于需要保证 hprof 文件已完整写入后再继续的调用方。
 */
bool HprofDump::ResumeAndWait(pid_t pid) {
  return impl_.ResumeAndWait(pid);
}

/**
 * 触发一次 hprof 堆快照写入，只应在 fork 出来的子进程中调用：
 * 子进程独享一份内存快照且即将退出，写文件耗多久都不会拖慢宿主 App。
 */
void HprofDump::DumpHeap(const char* filename) {
  return impl_.DumpHeap(filename);
}

}  // namespace leak_monitor
}  // namespace kwai