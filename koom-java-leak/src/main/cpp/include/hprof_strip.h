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

#ifndef KOOM_HPROF_STRIP_H
#define KOOM_HPROF_STRIP_H

#include <android-base/macros.h>

#include <memory>
#include <string>

namespace kwai {
namespace leak_monitor {

/**
 * hprof裁剪核心类：通过xhook拦截open/write，在dump过程中识别并跳过
 * zygote/image等系统堆空间以及基础类型数组内容，边写边裁剪，
 * 从而在不做二次全文件扫描的前提下缩小最终hprof文件体积。
 * 以单例形式存在，因为open/write的hook回调是C风格全局函数，
 * 需要一个全局可达的实例来保存跨调用的裁剪状态。
 */
class HprofStrip {
 public:
  // 获取全局唯一实例，供静态hook回调函数转发调用
  static HprofStrip &GetInstance();
  // 注册open/write的xhook，使后续系统调用被本类拦截
  static void HookInit();
  // 拦截到open调用后的真实处理逻辑：放行调用并识别目标hprof文件的fd
  int HookOpenInternal(const char *path_name, int flags, ...);
  // 拦截到write调用后的真实处理逻辑：对命中hprof fd的写入做裁剪
  ssize_t HookWriteInternal(int fd, const void *buf, ssize_t count);
  // 查询open的hook是否命中过目标hprof文件，用于判断裁剪是否生效
  bool IsHookSuccess() const;
  // 由JNI层传入Kotlin侧生成的hprof文件名，用于匹配目标fd
  void SetHprofName(const char *hprof_name);

 private:
  HprofStrip();
  ~HprofStrip() = default;
  // 禁止拷贝/赋值，保证HprofStrip只存在GetInstance()返回的这一份状态
  DISALLOW_COPY_AND_ASSIGN(HprofStrip);

  // 按hprof大端(big-endian)格式，从buf指定index处读出一个2字节短整数
  static int GetShortFromBytes(const unsigned char *buf, int index);
  // 按hprof大端(big-endian)格式，从buf指定index处读出一个4字节整数
  static int GetIntFromBytes(const unsigned char *buf, int index);
  // 根据hprof基础类型编码，返回该类型在hprof二进制流中占用的字节数
  static int GetByteSizeFromType(unsigned char basic_type);

  // 递归解析heap dump子记录(tag)流，定位需要裁剪的字节区间
  int ProcessHeap(const void *buf, int first_index, int max_len,
                  int heap_serial_no, int array_serial_no);

  // 保证count字节全部写入fd，处理write可能出现的部分写入(short write)
  static size_t FullyWrite(int fd, const void *buf, ssize_t count);
  // 每次拦截到hprof写入前，重置本次裁剪相关的中间状态
  void reset();

  int hprof_fd_;
  int strip_bytes_sum_;
  int heap_serial_num_;
  int hook_write_serial_num_;
  int strip_index_;

  bool is_hook_success_;
  bool is_current_system_heap_;

  std::string hprof_name_;

  // 单次write回调中，可能命中的裁剪区间数量上限，
  // 按较大的经验值预留，避免在hook回调中做动态内存分配
  static constexpr int kStripListLength = 65536 * 2 * 2 + 2;
  // 保存需要裁剪的[起点,终点)区间对，下标i*2/i*2+1分别对应第i个区间的左右边界
  int strip_index_list_pair_[kStripListLength];
};

}  // namespace leak_monitor
}  // namespace kwai

#endif  // KOOM_HPROF_STRIP_H