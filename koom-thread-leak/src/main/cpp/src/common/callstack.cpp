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

#include "callstack.h"

#include <dlfcn.h>
#include <kwai_linker/kwai_dlfcn.h>

#include "bionic/tls.h"
#include "bionic/tls_defines.h"

namespace koom {

const char *callstack_tag = "koom-callstack";

//静态变量初始化
pthread_key_t CallStack::pthread_key_self;
dump_java_stack_above_o_ptr CallStack::dump_java_stack_above_o;
dump_java_stack_ptr CallStack::dump_java_stack;

std::atomic<bool> CallStack::disableJava;
std::atomic<bool> CallStack::disableNative;
std::mutex CallStack::dumpJavaLock;

std::atomic<bool> CallStack::inSymbolize;

unwindstack::UnwinderFromPid *CallStack::unwinder;

/**
 * 解析 ART 内部符号，为后续 Java 堆栈捕获做准备。
 * 不同 Android 版本 ART 内部实现（DumpJavaStack 签名、pthread_key_self 是否存在）不同，
 * 因此这里按 API level 分别 dlopen("libart.so") + dlsym 找到对应的私有符号（这些符号不在公开 NDK 头文件中）。
 */
void CallStack::Init() {
  if (koom::Util::AndroidApi() < __ANDROID_API_L__) {
    koom::Log::error(callstack_tag, "android api < __ANDROID_API_L__");
    return;
  }
  // 打开 libart.so 以便查找其内部（未导出到 NDK 的）符号。
  void *handle =
      kwai::linker::DlFcn::dlopen("libart.so", RTLD_LAZY | RTLD_LOCAL);
  if (koom::Util::AndroidApi() >= __ANDROID_API_O__) {
    dump_java_stack_above_o = reinterpret_cast<
        dump_java_stack_above_o_ptr>(kwai::linker::DlFcn::dlsym(
        handle,
        "_ZNK3art6Thread13DumpJavaStackERNSt3__113basic_ostreamIcNS1_11char_"
        "traitsIcEEEEbb"));
    if (dump_java_stack_above_o == nullptr) {
      koom::Log::error(callstack_tag, "dump_java_stack_above_o is null");
    }
  } else if (koom::Util::AndroidApi() >= __ANDROID_API_L__) {
    dump_java_stack = reinterpret_cast<
        dump_java_stack_ptr>(kwai::linker::DlFcn::dlsym(
        handle,
        "_ZNK3art6Thread13DumpJavaStackERNSt3__113basic_ostreamIcNS1_11char_"
        "traitsIcEEEE"));
    if (dump_java_stack == nullptr) {
      koom::Log::error(callstack_tag, "dump_java_stack is null");
    }
  }

  if (koom::Util::AndroidApi() < __ANDROID_API_N__) {
    auto *pthread_key_self_art = (pthread_key_t *)kwai::linker::DlFcn::dlsym(
        handle, "_ZN3art6Thread17pthread_key_self_E");
    if (pthread_key_self_art != nullptr) {
      pthread_key_self = reinterpret_cast<pthread_key_t>(*pthread_key_self_art);
    } else {
      koom::Log::error(callstack_tag, "pthread_key_self_art is null");
    }
  }

  // 用完立即关闭句柄，避免长期占用 libart.so 的引用计数（符号地址已缓存，不需要保持句柄打开）。
  kwai::linker::DlFcn::dlclose(handle);
}

/**
 * 获取当前 native 线程对应的 ART Thread* 对象指针（后续用于 DumpJavaStack）。
 * Android N 及以上，ART Thread 指针缓存在 bionic TLS 的固定槽位 TLS_SLOT_ART_THREAD_SELF 中，直接读取即可；
 * N 之前则需要通过 pthread_getspecific 从 ART 私有的 pthread_key_self 中取出（Init 中解析得到）。
 */
void *CallStack::GetCurrentThread() {
  if (koom::Util::AndroidApi() >= __ANDROID_API_N__) {
    return __get_tls()[TLS_SLOT_ART_THREAD_SELF];
  }
  if (koom::Util::AndroidApi() >= __ANDROID_API_L__) {
    return pthread_getspecific(pthread_key_self);
  }
  koom::Log::info(callstack_tag, "GetCurrentThread return");
  return nullptr;
}

/**
 * 捕获指定 ART 线程当前的 Java 调用栈，写入 os。
 * 通过反射调用 ART 内部私有函数 art::Thread::DumpJavaStack 实现（该函数未导出给 NDK 使用）。
 * 用于在线程创建时记录“是谁（哪段 Java 代码）创建了这个线程”，便于泄漏排查。
 */
void CallStack::JavaStackTrace(void *thread, std::ostream &os) {
  if (disableJava.load()) {
    os << "no java stack when dumping";
    return;
  }
  if (dumpJavaLock.try_lock()) {
    if (koom::Util::AndroidApi() >= __ANDROID_API_O__) {
      //不dump locks，有稳定性问题
      dump_java_stack_above_o(thread, os, true, false);
    } else if (koom::Util::AndroidApi() >= __ANDROID_API_L__) {
      dump_java_stack(thread, os);
    }
    dumpJavaLock.unlock();
  }
}

/**
 * 在 pthread_create hook 中被调用，快速捕获当前 native 调用栈的裸 PC 序列。
 * 底层走 koom-common 提供的 frame_pointer_unwind：沿 arm64 的 x29（帧指针）链逐帧回溯，
 * 不解析 .eh_frame/DWARF CFI，速度远快于标准 unwinder；
 * 由于每次 pthread_create 都会走到这里（潜在热点路径），必须选用这种低开销的回溯方式，
 * 这也是本模块被限定为仅支持 arm64-v8a 的核心原因：ARM32 下 Thumb/ARM 混合指令集切换时
 * 帧指针寄存器约定不统一，无法可靠地维护一条连续的 FP 链。
 */
size_t CallStack::FastUnwind(uintptr_t *buf, size_t num_entries) {
  if (disableNative.load()) {
    return 0;
  }
  return frame_pointer_unwind(buf, num_entries);
}

/**
 * 把 FastUnwind 采集到的裸 PC 地址，在需要生成报告时才符号化为可读的
 * "函数名+偏移 (库名:偏移)" 字符串（符号化本身较慢，因此延后到上报阶段按需执行，而不是在热路径上做）。
 */
std::string CallStack::SymbolizePc(uintptr_t pc, int index) {
  if (inSymbolize.load()) return "";
  inSymbolize = true;

  if (unwinder == nullptr) {
    // 基于当前进程 pid 构造 unwindstack 的符号化器：它会读取 /proc/self/maps 定位 pc 落在哪个
    // 已加载的库里，再解析该库 ELF 文件的符号表，从而把裸地址还原成函数名+偏移。
    unwinder = new unwindstack::UnwinderFromPid(
        koom::Constant::kMaxCallStackDepth, getpid(),
        unwindstack::Regs::CurrentArch());
    unwinder->Init();
    unwinder->SetDisplayBuildID(true);
    unwinder->SetRegs(unwindstack::Regs::CreateFromLocal());
  }
  std::string format;
  // 只根据 pc 查找其所属的内存映射区间和符号，不依赖寄存器上下文做逐帧回溯（因为帧序列已由 FastUnwind 采集）。
  unwindstack::FrameData data = unwinder->BuildFrameFromPcOnly(pc);
  if (data.map_name.find("libkoom-thread") != std::string::npos) {
    inSymbolize = false;
    return "";
  }
  data.num = index;
  format = unwinder->FormatFrame(data);

  inSymbolize = false;
  return format;
}

/** 关闭 Java 堆栈捕获（对应 Java 层 NativeHandler.disableJavaStack）。 */
void CallStack::DisableJava() { disableJava = true; }

/** 关闭 native 堆栈捕获（对应 Java 层 NativeHandler.disableNativeStack）。 */
void CallStack::DisableNative() { disableNative = true; }
}  // namespace koom
