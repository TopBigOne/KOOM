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

#include "looper.h"

#include <android/log.h>
#include <fcntl.h>
#include <jni.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>

#include "log.h"

#define TAG "koom-looper"
#define LOGV(...) koom::Log::info(TAG, __VA_ARGS__);

// 队列中的一个节点：what 是消息类型（对应 HookAction），obj 是携带的数据指针，quit 标记这是“退出”哨兵消息。
struct LooperMessage {
  int what;
  void *obj;
  LooperMessage *next;
  bool quit;
};

/**
 * pthread_create 的入口跳板函数：先给线程设置一个可在 /proc/[pid]/task 或 logcat 中辨识的名字，
 * 再进入真正的消息循环 loop()。
 */
void *looper::trampoline(void *p) {
  // 设置线程名，方便在 `adb shell ps -T` / systrace / 崩溃日志中识别出这是本模块的后台线程。
  prctl(PR_SET_NAME, "koom-looper");
  ((looper *)p)->loop();
  return nullptr;
}

/**
 * 构造函数：初始化两个信号量并创建后台工作线程。
 * headWriteProtect 初值为 1，充当互斥锁保护链表；headDataAvailable 初值为 0，
 * 充当计数信号量，用来在“有新消息”和“工作线程被唤醒”之间建立生产者-消费者关系。
 */
looper::looper() {
  sem_init(&headDataAvailable, 0, 0);
  sem_init(&headWriteProtect, 0, 1);
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  // 创建后台工作线程执行 loop()；本模块自身创建的这类线程会被 ignore_libs 过滤，不会 hook 自己。
  pthread_create(&worker, &attr, trampoline, this);
  running = true;
}

/** 析构函数：若工作线程仍在运行，先调用 quit() 让其处理完剩余消息并退出，避免内存泄漏或悬挂线程。 */
looper::~looper() {
  if (running) {
    LOGV(
        "Looper deleted while still running. Some messages will not be "
        "processed");
    quit();
  }
}

/**
 * 向队列投递一条消息（生产者接口）。这是 hook 回调等调用方与本 looper 交互的唯一入口：
 * 调用方把耗时的实际处理工作转移给后台线程，自身立即返回，从而不阻塞被 hook 的原始 API 调用。
 */
void looper::post(int what, void *data, bool flush) {
  auto *msg = new LooperMessage();
  msg->what = what;
  msg->obj = data;
  msg->next = nullptr;
  msg->quit = false;
  addMsg(msg, flush);
}

/**
 * 把一条消息追加到链表尾部（可选先清空队列），并通过信号量通知等待中的消费者线程。
 * headWriteProtect 在此充当互斥锁：sem_wait/sem_post 包裹对 head/tail 的访问，防止和 loop() 中的出队操作产生数据竞争。
 */
void looper::addMsg(LooperMessage *msg, bool flush) {
  sem_wait(&headWriteProtect);
  LooperMessage *h = head;
  if (flush) {
    while (h) {
      LooperMessage *next = h->next;
      delete h;
      h = next;
    }
    h = nullptr;
  }
  if (h != nullptr) {
    tail->next = msg;
    tail = msg;
  } else {
    head = msg;
    tail = msg;
  }
  sem_post(&headWriteProtect);
  // 唤醒（或为下一次唤醒累计计数）阻塞在 loop() 里 sem_wait(&headDataAvailable) 的消费者线程。
  sem_post(&headDataAvailable);
}

/**
 * 后台工作线程的主循环（消费者）：没有消息时阻塞休眠在信号量上，不占用 CPU；
 * 一旦被唤醒就取出队首消息并分发给 handle() 处理，直到收到 quit 哨兵消息为止。
 * 把这部分处理和调用方（生产者）解耦，是本模块能让 pthread_create/exit/join/detach 的 hook 保持轻量的关键。
 */
void looper::loop() {
  while (true) {
    // wait for available message
    sem_wait(&headDataAvailable);
    // get next available message
    sem_wait(&headWriteProtect);
    LooperMessage *msg = head;
    if (msg == nullptr) {
      LOGV("no msg");
      sem_post(&headWriteProtect);
      continue;
    }
    head = msg->next;
    sem_post(&headWriteProtect);
    if (msg->quit) {
      LOGV("quitting");
      delete msg;
      return;
    }
    LOGV("processing msg %d", msg->what);
    handle(msg->what, msg->obj);
    delete msg;
  }
}

/**
 * 请求后台线程退出：投递一条特殊的 quit 消息，并阻塞等待工作线程结束（pthread_join），
 * 确保 loop() 已经安全返回、不再访问本对象的成员之后，再释放信号量资源。
 */
void looper::quit() {
  LOGV("quit");
  auto *msg = new LooperMessage();
  msg->what = 0;
  msg->obj = nullptr;
  msg->next = nullptr;
  msg->quit = true;
  addMsg(msg, false);
  void *val;
  // 等待工作线程真正退出（回收其内核线程资源），这里主动 join，因此不会造成本模块自身的线程泄漏。
  pthread_join(worker, &val);
  sem_destroy(&headDataAvailable);
  sem_destroy(&headWriteProtect);
  running = false;
}

/** 默认的消息处理实现，仅打印日志；子类（如 HookLooper）重写它以实现具体的业务分发。 */
void looper::handle(int what, void *obj) {
  LOGV("dropping msg %d %p", what, obj);
}
