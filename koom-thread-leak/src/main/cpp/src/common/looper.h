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

#include <pthread.h>
#include <semaphore.h>
struct LooperMessage;

// 通用的“单消费者消息循环”基础设施：内部维护一个专用工作线程 + 一条由信号量保护的单链表队列。
// 目的是把耗时/需要串行化的工作从调用方（往往是热路径，如 hook 回调）搬到后台线程异步处理，
// 调用方只需 post() 一条消息即可立即返回。HookLooper 在此基础上扩展出具体的业务处理逻辑。
class looper {
 public:
  looper();
  ~looper();
  virtual void post(int what, void *data, bool flush = false);
  void quit();
  virtual void handle(int what, void *data);

 private:
  void addMsg(LooperMessage *msg, bool flush);
  static void *trampoline(void *p);
  void loop();
  LooperMessage *head = nullptr;
  LooperMessage *tail = nullptr;
  // 后台工作线程，唯一的消息消费者，由构造函数中的 pthread_create 创建。
  pthread_t worker;
  // 保护 head/tail 链表在生产者（post 调用方线程）和消费者（worker 线程）之间的并发访问。
  sem_t headWriteProtect;
  // 计数信号量：每 post 一条消息 sem_post 一次，worker 线程 sem_wait 阻塞等待，
  // 从而实现“无消息时休眠、有消息时唤醒”的高效等待，避免忙轮询。
  sem_t headDataAvailable;
  bool running;
};