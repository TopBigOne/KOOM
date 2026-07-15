#include "thread_holder.h"

#include <filesystem>
#include <regex>

#include "koom.h"
#include "thread_hook.h"

namespace koom {

const char *holder_tag = "koom-holder";

/**
 * 状态机入口：新线程刚创建（HookThreadStart 中采集完信息后）时调用，登记其初始状态到 threadMap。
 * isThreadDetached 反映的是 POSIX 线程创建属性——如果创建时就指定了 PTHREAD_CREATE_DETACHED，
 * 该线程退出后内核会自动回收资源，不需要也不允许被 join，因此天然不会被判定为泄漏；
 * 只有默认的 joinable 线程才需要后续被 JoinThread/DetachThread/ExitThread 持续跟踪状态变化。
 * 同时负责把创建时刻采集的裸 PC 调用栈（native）和 Java 堆栈文本拼接、符号化成最终可读的字符串，
 * 供之后一旦判定泄漏时能直接用于生成报告。
 */
void ThreadHolder::AddThread(int tid, pthread_t threadId, bool isThreadDetached,
                             int64_t start_time, ThreadCreateArg *create_arg) {
  bool valid = threadMap.count(threadId) > 0;
  if (valid) return;

  koom::Log::info(holder_tag, "AddThread tid:%d pthread_t:%p", tid, threadId);
  auto &item = threadMap[threadId];
  item.Clear();
  item.thread_internal_id = threadId;
  item.thread_detached = isThreadDetached;
  item.startTime = start_time;
  item.create_time = create_arg->time;
  item.id = tid;
  std::string &stack = item.create_call_stack;
  stack.assign("");
  try {
    // native stack
    int ignoreLines = 0;
    for (int index = 0; index < koom::Constant::kMaxCallStackDepth; ++index) {
      uintptr_t p = create_arg->pc[index];
      if (p == 0) continue;
      // koom::Log::info(holder_tag, "unwind native callstack #%d pc%p", index,
      // p);
      // 把 FastUnwind 采集到的裸 PC 逐个符号化成 "函数+偏移 (库:偏移)" 文本行，拼接成完整的 native 调用栈。
      std::string line = koom::CallStack::SymbolizePc(p, index - ignoreLines);
      if (line.empty()) {
        ignoreLines++;
      } else {
        line.append("\n");
        stack.append(line);
      }
    }
    // java stack
    std::vector<std::string> splits =
        koom::Util::Split(create_arg->java_stack.str(), '\n');
    for (const auto &split : splits) {
      if (split.empty()) continue;
      std::string line;
      line.append("#");
      line.append(split);
      line.append("\n");
      stack.append(line);
    }
    //空白堆栈，去掉##
    if (stack.size() == 3) stack.assign("");
  } catch (const std::bad_alloc &) {
    stack.assign("error:bad_alloc");
  }
  delete create_arg;
  koom::Log::info(holder_tag, "AddThread finish");
}

/**
 * 状态机转换：处理某个线程被 pthread_join 的事件。
 * POSIX 语义中 join 会阻塞等待目标线程结束并回收其内核资源，相当于线程生命周期被“安全终结”，
 * 因此这里直接把该线程标记为 thread_detached=true（复用该字段表示“已被正确回收，不会泄漏”）。
 * 若该 pthread_t 已不在 threadMap（比如线程已退出并进了 leakThreadMap），
 * 说明 join 发生在 ExitThread 判定泄漏之后，此时需要把它从 leakThreadMap 中移除，撤销误判。
 */
void ThreadHolder::JoinThread(pthread_t threadId) {
  bool valid = threadMap.count(threadId) > 0;
  koom::Log::info(holder_tag, "JoinThread tid:%p", threadId);
  if (valid) {
    threadMap[threadId].thread_detached = true;
  } else {
    leakThreadMap.erase(threadId);
  }
}

/**
 * 状态机转换：处理某个线程调用 pthread_exit 真正退出的事件，是判定“是否泄漏”的关键节点。
 * 依据 POSIX 线程语义：一个 joinable 线程退出后，如果没有被 pthread_join 或 pthread_detach 过
 * （即 item.thread_detached 仍为 false），它的内核线程资源（线程描述符、内核栈等）就不会被回收，
 * 会一直占用直到进程结束——这就是本模块要检测的"线程泄漏"，因此把它从 threadMap 移入
 * leakThreadMap，交由 ReportThreadLeak 在延迟一段时间后确认并上报（避免和随后立刻发生的 join/detach 竞争造成误报）。
 */
void ThreadHolder::ExitThread(pthread_t threadId, std::string &threadName,
                              long long int time) {
  bool valid = threadMap.count(threadId) > 0;
  if (!valid) return;
  auto &item = threadMap[threadId];
  koom::Log::info(holder_tag, "ExitThread tid:%p name:%s", threadId,
                  item.name.c_str());

  item.exitTime = time;
  item.name.assign(threadName);
  if (!item.thread_detached) {
    // 泄露了
    koom::Log::error(holder_tag,
                     "Exited thread Leak! Not joined or detached!\n tid:%p",
                     threadId);
    leakThreadMap[threadId] = item;
  }
  threadMap.erase(threadId);
  koom::Log::info(holder_tag, "ExitThread finish");
}

/**
 * 状态机转换：处理某个线程被 pthread_detach 的事件。
 * detach 会把一个 joinable 线程转换为“退出后自动回收资源、且不能再被 join”的状态，
 * 同样标记为不会造成泄漏；若线程已经退出并进入 leakThreadMap（先 exit 后 detach 的时序），
 * 则从泄漏表中撤销该记录。
 */
void ThreadHolder::DetachThread(pthread_t threadId) {
  bool valid = threadMap.count(threadId) > 0;
  koom::Log::info(holder_tag, "DetachThread tid:%p", threadId);
  if (valid) {
    threadMap[threadId].thread_detached = true;
  } else {
    leakThreadMap.erase(threadId);
  }
}

/** 把单个线程的关键信息（内核 tid、pthread_t、各阶段时间戳、名称、创建调用栈）序列化成一个 JSON 对象。 */
void ThreadHolder::WriteThreadJson(
    rapidjson::Writer<rapidjson::StringBuffer> &writer,
    ThreadItem &thread_item) {
  //写入单个thread数据
  writer.StartObject();

  writer.Key("tid");
  writer.Uint(thread_item.id);

  writer.Key("interal_id");
  writer.Uint(thread_item.thread_internal_id);

  writer.Key("createTime");
  writer.Int64(thread_item.create_time);

  writer.Key("startTime");
  writer.Int64(thread_item.startTime);

  writer.Key("endTime");
  writer.Int64(thread_item.exitTime);

  writer.Key("name");
  writer.String(thread_item.name.c_str());

  // 这里先注释掉，确认一下是不是这里的转换有问题，是的话，再处理
  writer.Key("createCallStack");
  auto stack = thread_item.create_call_stack.c_str();
  writer.String(stack);

  writer.EndObject();
}

/**
 * 流水线的最后一步——报告：由 ACTION_REFRESH 触发，遍历 leakThreadMap 中的疑似泄漏线程，
 * 只上报那些“退出时间 + 延迟阈值(threadLeakDelay) 早于当前时间”且尚未上报过的记录
 * （延迟判定是为了容忍调用方在退出后短暂延迟才 join/detach 的正常场景，减少误报），
 * 汇总成一份 JSON 后通过 JavaCallback 回调给 Java 层，最后清理掉已上报的记录。
 */
void ThreadHolder::ReportThreadLeak(long long time) {
  int needReport{};
  const char *type = "detach_leak";
  auto delay = threadLeakDelay * 1000000LL;  // ms -> ns
  rapidjson::StringBuffer jsonBuf;
  rapidjson::Writer<rapidjson::StringBuffer> writer(jsonBuf);
  writer.StartObject();

  writer.Key("leakType");
  writer.String(type);

  writer.Key("threads");
  writer.StartArray();

  for (auto &item : leakThreadMap) {
    if (item.second.exitTime + delay < time && !item.second.thread_reported) {
      koom::Log::info(holder_tag, "ReportThreadLeak %ld, %ld, %ld",
                      item.second.exitTime, time, delay);
      needReport++;
      item.second.thread_reported = true;
      WriteThreadJson(writer, item.second);
    }
  }
  writer.EndArray();
  writer.EndObject();
  koom::Log::info(holder_tag, "ReportThreadLeak %d", needReport);
  if (needReport) {
    JavaCallback(jsonBuf.GetString());
    // clean up
    auto it = leakThreadMap.begin();
    for (; it != leakThreadMap.end();) {
      if (it->second.thread_reported) {
        leakThreadMap.erase(it++);
      } else {
        it++;
      }
    }
  }
}
}  // namespace koom