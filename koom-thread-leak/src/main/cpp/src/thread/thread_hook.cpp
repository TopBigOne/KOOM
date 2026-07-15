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

#include "thread_hook.h"

#include <dlopencb.h>
#include <kwai_util/kwai_macros.h>
#include <link.h>
#include <sys/prctl.h>
#include <syscall.h>
#include <xhook.h>

namespace koom {

const char *thread_tag = "thread-hook";

// 不对这些库做 pthread hook：koom-thread 是本模块自身（避免 hook 自己造成递归/自我干扰），
// liblog.so/perfd/memtrack 等系统底层库过早或过于频繁地创建线程，hook 它们收益低且有更高的稳定性风险。
const char *ignore_libs[] = {"koom-thread", "liblog.so", "perfd", "memtrack"};

static bool IsLibIgnored(const std::string &lib) {
  for (const auto &ignoreLib : ignore_libs) {
    if (lib.find(ignoreLib) != -1) {
      return true;
    }
  }
  return false;
}

// dl_iterate_phdr 的回调，用于枚举当前进程已加载的所有 so，收集到 libs 集合中供后续统一 hook。
int Callback(struct dl_phdr_info *info, size_t size, void *data) {
  auto *libs = static_cast<std::set<std::string> *>(data);
  libs->insert(info->dlpi_name);
  return 0;
}

/**
 * hook 流水线的启动函数：先拿到当前进程已加载的全部 so 列表做一次全量 hook，
 * 再向 DlopenCb 注册回调，保证运行期后续动态 dlopen 加载的新库也会被自动 hook。
 */
void ThreadHooker::InitHook() {
  koom::Log::info(thread_tag, "HookSo init hook");
  std::set<std::string> libs;
  DlopenCb::GetInstance().GetLoadedLibs(libs);
  HookLibs(libs, Constant::kDlopenSourceInit);
  DlopenCb::GetInstance().AddCallback(DlopenCallback);
}

/** dlopen 回调：新库被加载时触发，对这批新库做增量 hook 注册。 */
void ThreadHooker::DlopenCallback(std::set<std::string> &libs, int source,
                                  std::string &source_lib) {
  HookLibs(libs, source);
}

/**
 * 对一批 so 逐个调用 RegisterSo 注册 xhook 规则，只要有任意一个库命中就调用 xhook_refresh
 * 让 xhook 真正遍历 ELF 的 PLT/GOT 段完成替换（xhook_register 本身只是记录规则，不会立即生效）。
 */
void ThreadHooker::HookLibs(std::set<std::string> &libs, int source) {
  koom::Log::info(thread_tag, "HookSo lib size %d", libs.size());
  if (libs.empty()) {
    return;
  }
  bool hooked = false;
  pthread_mutex_lock(&DlopenCb::hook_mutex);
  xhook_clear();
  for (const auto &lib : libs) {
    hooked |= ThreadHooker::RegisterSo(lib, source);
  }
  if (hooked) {
    // xhook_refresh 会真正遍历目标 so 的 PLT/GOT 表，把 pthread_create/join/detach/exit 等符号的
    // GOT 表项改写为指向本模块的 Hook* 包装函数的地址——不修改目标 so 的代码段本身，只重写其导入表，
    // 因此调用点无需改动即可“路由”到本模块的 wrapper，wrapper 再转调用真正的 libc 实现。
    int result = xhook_refresh(0);
    koom::Log::info(thread_tag, "HookSo lib Refresh result %d", result);
  }
  pthread_mutex_unlock(&DlopenCb::hook_mutex);
}

/**
 * 为单个 so 注册 xhook 规则（登记阶段，尚未真正生效，需配合 xhook_refresh）。
 * 命中黑名单的库直接跳过，其余库对 pthread_create/detach/join/exit 四个符号分别登记替换函数。
 */
bool ThreadHooker::RegisterSo(const std::string &lib, int source) {
  if (IsLibIgnored(lib)) {
    return false;
  }
  auto lib_ctr = lib.c_str();
  koom::Log::info(thread_tag, "HookSo %d %s", source, lib_ctr);
  // 以下四个 xhook_register 分别登记对 pthread_create/detach/join/exit 的 PLT/GOT hook：
  // 之后该 so 内对这些符号的调用都会先落入本模块的 HookThread* 包装函数。
  xhook_register(lib_ctr, "pthread_create",
                 reinterpret_cast<void *>(HookThreadCreate), nullptr);
  xhook_register(lib_ctr, "pthread_detach",
                 reinterpret_cast<void *>(HookThreadDetach), nullptr);
  xhook_register(lib_ctr, "pthread_join",
                 reinterpret_cast<void *>(HookThreadJoin), nullptr);
  xhook_register(lib_ctr, "pthread_exit",
                 reinterpret_cast<void *>(HookThreadExit), nullptr);

  return true;
}

/**
 * pthread_create 的 hook 替身：在真正创建线程之前，先在“创建者线程”上下文中完成两件事——
 * 1) 捕获当前 Java 调用栈（如果处在 ART 线程上）；2) 用帧指针快速回溯捕获当前 native 调用栈；
 * 然后把新线程的入口替换为 HookThreadStart（而非调用方原始的 start_rtn），
 * 以便新线程启动后能先补充记录内核 tid / detach 状态等只有在新线程自己身上才能获取的信息。
 */
int ThreadHooker::HookThreadCreate(pthread_t *tidp, const pthread_attr_t *attr,
                                   void *(*start_rtn)(void *), void *arg) {
  if (hookEnabled() && start_rtn != nullptr) {
    auto time = Util::CurrentTimeNs();
    koom::Log::info(thread_tag, "HookThreadCreate");
    auto *hook_arg = new StartRtnArg(arg, Util::CurrentTimeNs(), start_rtn);
    auto *thread_create_arg = hook_arg->thread_create_arg;
    void *thread = koom::CallStack::GetCurrentThread();
    if (thread != nullptr) {
      koom::CallStack::JavaStackTrace(thread,
                                      hook_arg->thread_create_arg->java_stack);
    }
    // 帧指针快速回溯：只在 arm64 上可靠，这也是本模块限定为 arm64-v8a-only 的原因之一。
    koom::CallStack::FastUnwind(thread_create_arg->pc,
                                koom::Constant::kMaxCallStackDepth);
    thread_create_arg->stack_time = Util::CurrentTimeNs() - time;
    // 关键点：把线程真正的入口函数替换成 HookThreadStart，而不是直接传 start_rtn，
    // 从而让新线程一启动就先回调到本模块完成 tid/detach 状态采集，再跳转执行调用方原始逻辑。
    return pthread_create(tidp, attr,
                          reinterpret_cast<void *(*)(void *)>(HookThreadStart),
                          reinterpret_cast<void *>(hook_arg));
  }
  return pthread_create(tidp, attr, start_rtn, arg);
}

/**
 * 新线程的真正入口（取代调用方原始的 start_rtn 被 pthread_create 调用）。
 * 在新线程自己的上下文里读取 detach 状态和内核 tid，把“线程已创建”事件（连同创建时调用栈）
 * 投递给后台 HookLooper 做记录，然后再跳转执行调用方真正的业务逻辑 start_rtn(arg)。
 */
ALWAYS_INLINE void ThreadHooker::HookThreadStart(void *arg) {
  koom::Log::info(thread_tag, "HookThreadStart");
  auto *hookArg = (StartRtnArg *)arg;
  pthread_attr_t attr;
  pthread_t self = pthread_self();
  int state = 0;
  if (pthread_getattr_np(self, &attr) == 0) {
    // 读取线程创建时的 detach 状态：PTHREAD_CREATE_DETACHED 表示这是一个"detached"线程，
    // 退出后内核会自动回收其资源，天然不存在“忘记 join/detach 导致泄漏”的风险；
    // 只有 PTHREAD_CREATE_JOINABLE（默认）的线程才需要被本模块持续跟踪。
    pthread_attr_getdetachstate(&attr, &state);
  }
  // syscall(SYS_gettid) 获取的是内核线程 ID（对应 /proc/[pid]/task/[tid] 和 logcat 中显示的 tid），
  // 它与 pthread_t（仅是 pthread 库在用户态维护的、跨进程/跨线程库实现不保证全局唯一的句柄）是两个不同的概念；
  // 上报和定位问题时需要展示/比对的是内核 tid，因此这里必须显式调用 gettid 系统调用获取，
  // 而不能依赖 pthread_self() 返回值。
  int tid = (int)syscall(SYS_gettid);
  koom::Log::info(thread_tag, "HookThreadStart %p, %d, %d", self, tid,
                  hookArg->thread_create_arg->stack_time);
  auto info = new HookAddInfo(tid, Util::CurrentTimeNs(), self,
                              state == PTHREAD_CREATE_DETACHED,
                              hookArg->thread_create_arg);

  // 投递 ACTION_ADD_THREAD 事件到后台 looper，由 ThreadHolder::AddThread 记录该线程的初始状态。
  sHookLooper->post(ACTION_ADD_THREAD, info);
  void *(*start_rtn)(void *) = hookArg->start_rtn;
  void *routine_arg = hookArg->arg;
  delete hookArg;
  // 完成记录后，才真正跳转执行调用方原本想要运行的线程函数。
  start_rtn(routine_arg);
}

/**
 * pthread_detach 的 hook 替身：detach 是 POSIX 线程状态机里把一个 joinable 线程
 * 转为“退出后自动回收资源、无需也不能再被 join”的关键动作。这里先异步记录该状态变化，
 * 再调用真正的 pthread_detach 完成实际的系统调用。
 */
int ThreadHooker::HookThreadDetach(pthread_t t) {
  if (!hookEnabled()) return pthread_detach(t);

  int c_tid = (int)syscall(SYS_gettid);
  koom::Log::info(thread_tag, "HookThreadDetach c_tid:%0x", c_tid);

  auto info = new HookInfo(t, Util::CurrentTimeNs());
  sHookLooper->post(ACTION_DETACH_THREAD, info);
  return pthread_detach(t);
}

/**
 * pthread_join 的 hook 替身：join 是显式回收一个 joinable 线程资源的正常途径。
 * 先异步记录“该线程已被 join”，再调用真正的 pthread_join（该调用会阻塞直到目标线程退出并回收其资源）。
 */
int ThreadHooker::HookThreadJoin(pthread_t t, void **return_value) {
  if (!hookEnabled()) return pthread_join(t, return_value);

  int c_tid = (int)syscall(SYS_gettid);
  koom::Log::info(thread_tag, "HookThreadJoin c_tid:%0x", c_tid);

  auto info = new HookInfo(t, Util::CurrentTimeNs());
  sHookLooper->post(ACTION_JOIN_THREAD, info);
  return pthread_join(t, return_value);
}

/**
 * pthread_exit 的 hook 替身：线程即将退出前的最后一次拦截点。
 * 记录退出事件（内核 tid + 线程名 + 时间戳），供后台在 ThreadHolder::ExitThread 中判断：
 * 如果这个线程是 joinable 且直到此刻仍未被 join/detach，就意味着它的内核线程资源
 * （线程描述符、内核栈等）在退出后将无人回收，一直占用到进程结束——这正是本模块要检测的"线程泄漏"。
 */
void ThreadHooker::HookThreadExit(void *return_value) {
  if (!hookEnabled()) pthread_exit(return_value);

  koom::Log::info(thread_tag, "HookThreadExit");
  // 同样需要内核 tid（而非 pthread_t 句柄）用于上报，便于和 /proc、logcat 等系统工具中看到的线程对应上。
  int tid = (int)syscall(SYS_gettid);
  char thread_name[16]{};
  // prctl(PR_GET_NAME) 读取当前线程通过 prctl(PR_SET_NAME,...) 或 pthread_setname_np 设置的名字，
  // 用于让上报信息里的线程更容易被人识别（而不是只有一个数字 tid）。
  prctl(PR_GET_NAME, thread_name);
  auto info =
      new HookExitInfo(pthread_self(), tid, thread_name, Util::CurrentTimeNs());
  sHookLooper->post(ACTION_EXIT_THREAD, info);
  pthread_exit(return_value);
}

/** 对外启动入口：委托给 InitHook 完成实际的 hook 注册工作。 */
void ThreadHooker::Start() { ThreadHooker::InitHook(); }

/** 对外停止入口：当前为空实现，真正的“停止生效”通过 koom::isRunning 开关在各 Hook* 函数中判断实现。 */
void ThreadHooker::Stop() {}

/** 是否应当记录 hook 事件；直接读取全局的 isRunning 标志（由 koom::Start/Stop 控制）。 */
bool ThreadHooker::hookEnabled() { return isRunning; }
}  // namespace koom