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
#include <hprof_dump.h>
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * JNI bridge for hprof dump
 * 提前完成一次性初始化（dlopen/dlsym 解析 ART 内部符号），
 * 避免在真正 dump 时（可能处于内存紧张场景）才做耗时的符号解析。
 */
JNIEXPORT void JNICALL Java_com_kwai_koom_fastdump_ForkJvmHeapDumper_nativeInit(
    JNIEnv *env ATTRIBUTE_UNUSED, jobject jobject ATTRIBUTE_UNUSED) {
  HprofDump::GetInstance().Initialize();
}

/**
 * JNI 入口：触发一次完整的“挂起 ART 虚拟机 -> fork() -> 父进程恢复 / 子进程 dump”流程。
 * 这样可以在不冻结（长时间阻塞）宿主 App 主流程的前提下，拿到 Java 堆的一致快照：
 * 子进程借助 fork() 的 Copy-on-Write 语义独享一份“时间点冻结”的地址空间副本，
 * 父进程则在极短暂停后立刻恢复运行。
 *
 * @param wait_pid 是否阻塞等待子进程退出（即 hprof 文件已完整落盘）后再返回，
 *                 若为 false 则父进程恢复后立即返回，dump 结果异步完成。
 */
JNIEXPORT jboolean JNICALL
Java_com_kwai_koom_fastdump_ForkJvmHeapDumper_forkDump(
    JNIEnv *env, jobject,
    jstring j_path, jboolean wait_pid
) {
  bool dump_success = false;
  auto c_path = env->GetStringUTFChars(j_path, nullptr);
  std::string file_name(c_path);
  env->ReleaseStringUTFChars(j_path, c_path);

  // SuspendAndFork()：先挂起所有 ART Java 线程，再 fork() 出子进程。
  // fork() 之后父子进程共享同一份物理内存页（只读），
  // 谁写入谁才触发内核复制该页（Copy-on-Write），因此 fork 本身耗时与堆大小无关，
  // 而子进程看到的是 fork 那一刻堆内容的完整快照，不受父进程后续写入影响。
  auto pid = HprofDump::GetInstance().SuspendAndFork();
  if (pid == 0) {
    // 子进程分支：fork() 之后子进程只包含发起调用的这一个线程，
    // 其余线程在子进程里“凭空消失”，因此这里绝不能再走可能依赖其他线程的逻辑。
    HprofDump::GetInstance().DumpHeap(file_name.c_str());
    // FastExit 内部使用 _exit() 而非 exit()：跳过 C++ 全局对象析构 / atexit 回调，
    // 因为子进程只是父进程状态的一个不完整拷贝（例如只有一个线程存活），
    // 继续执行这些清理逻辑可能访问到已经不一致的全局状态，导致崩溃或未定义行为。
    FastExit(0);
  } else if (pid > 0) {
    // 父进程分支：pid 是子进程的 pid，需要尽快 Resume 恢复所有被挂起的线程，
    // 让宿主 App 的暂停时间降到最短（通常 <20ms）。
    dump_success =
        JNI_TRUE == wait_pid
            // ResumeAndWait 内部会 waitpid 阻塞等待子进程退出，
            // 用于保证调用方拿到结果时 hprof 文件已经完整写入磁盘。
            ? HprofDump::GetInstance().ResumeAndWait(pid)
            : HprofDump::GetInstance().Resume();
  }

  return dump_success;
}

#ifdef __cplusplus
}
#endif
