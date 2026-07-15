/*
 * Copyright (c) 2020. Kwai, Inc. All rights reserved.
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
 * Created by lirui on 2019-12-17.
 *
 */

#include <android/log.h>
#include <fcntl.h>
#include <hprof_strip.h>
#include <kwai_util/kwai_macros.h>
#include <unistd.h>
#include <xhook.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>

#define LOG_TAG "HprofCrop"

namespace kwai {
namespace leak_monitor {

// hprof文件在二进制层面是一串"类型(tag)+长度+内容"的记录(record)组成的数据流：
// 每个顶层记录由1字节tag、4字节时间戳、4字节记录长度、以及对应长度的payload构成，
// 解析时需要顺序读tag、按长度跳到下一条记录，这也是本文件裁剪逻辑的基础。
// 以下枚举即为顶层记录的tag取值(对应上面提到的每条记录开头的1字节tag)。
enum HprofTag {
  HPROF_TAG_STRING = 0x01,
  HPROF_TAG_LOAD_CLASS = 0x02,
  HPROF_TAG_UNLOAD_CLASS = 0x03,
  HPROF_TAG_STACK_FRAME = 0x04,
  HPROF_TAG_STACK_TRACE = 0x05,
  HPROF_TAG_ALLOC_SITES = 0x06,
  HPROF_TAG_HEAP_SUMMARY = 0x07,
  HPROF_TAG_START_THREAD = 0x0A,
  HPROF_TAG_END_THREAD = 0x0B,
  HPROF_TAG_HEAP_DUMP = 0x0C,
  HPROF_TAG_HEAP_DUMP_SEGMENT = 0x1C,
  HPROF_TAG_HEAP_DUMP_END = 0x2C,
  HPROF_TAG_CPU_SAMPLES = 0x0D,
  HPROF_TAG_CONTROL_SETTINGS = 0x0E,
};

// HPROF_TAG_HEAP_DUMP/HPROF_TAG_HEAP_DUMP_SEGMENT记录的payload本身又是一串
// 子记录(sub-record)构成的tag流，下面的枚举即为这些堆内子记录的tag取值，
// 例如GC Root、类信息、实例数据、数组数据等，ProcessHeap就是逐个解析这层子记录。
enum HprofHeapTag {
  // Traditional.
  HPROF_ROOT_UNKNOWN = 0xFF,
  HPROF_ROOT_JNI_GLOBAL = 0x01,
  HPROF_ROOT_JNI_LOCAL = 0x02,
  HPROF_ROOT_JAVA_FRAME = 0x03,
  HPROF_ROOT_NATIVE_STACK = 0x04,
  HPROF_ROOT_STICKY_CLASS = 0x05,
  HPROF_ROOT_THREAD_BLOCK = 0x06,
  HPROF_ROOT_MONITOR_USED = 0x07,
  HPROF_ROOT_THREAD_OBJECT = 0x08,
  HPROF_CLASS_DUMP = 0x20,
  HPROF_INSTANCE_DUMP = 0x21,
  HPROF_OBJECT_ARRAY_DUMP = 0x22,
  HPROF_PRIMITIVE_ARRAY_DUMP = 0x23,

  // Android.
  HPROF_HEAP_DUMP_INFO = 0xfe,
  HPROF_ROOT_INTERNED_STRING = 0x89,
  HPROF_ROOT_FINALIZING = 0x8a,  // Obsolete.
  HPROF_ROOT_DEBUGGER = 0x8b,
  HPROF_ROOT_REFERENCE_CLEANUP = 0x8c,  // Obsolete.
  HPROF_ROOT_VM_INTERNAL = 0x8d,
  HPROF_ROOT_JNI_MONITOR = 0x8e,
  HPROF_UNREACHABLE = 0x90,                  // Obsolete.
  HPROF_PRIMITIVE_ARRAY_NODATA_DUMP = 0xc3,  // Obsolete.
};

// Java基础类型在hprof格式中的编码值(对应JVM TI hprof规范的Basic Type)，
// 用于在类字段、数组元素等变长结构中，根据类型算出该值占用的字节数。
enum HprofBasicType {
  hprof_basic_object = 2,
  hprof_basic_boolean = 4,
  hprof_basic_char = 5,
  hprof_basic_float = 6,
  hprof_basic_double = 7,
  hprof_basic_byte = 8,
  hprof_basic_short = 9,
  hprof_basic_int = 10,
  hprof_basic_long = 11,
};

// HPROF_HEAP_DUMP_INFO子记录标识后续对象属于哪一块堆空间：
// ART把内存分为zygote(所有进程共享的预加载堆)、image(系统预置类的只读堆)、
// app(应用自身分配的堆)几类；zygote/image里的对象与业务侧内存泄漏分析无关，
// 是本模块裁剪的主要目标(is_current_system_heap_即由此判断)。
enum HprofHeapId {
  HPROF_HEAP_DEFAULT = 0,
  HPROF_HEAP_ZYGOTE = 'Z',
  HPROF_HEAP_APP = 'A',
  HPROF_HEAP_IMAGE = 'I',
};

// hprof格式中各字段的固定字节宽度，解析时按这些常量做指针/下标偏移，
// 而不必引入通用的变长字段解析器，兼顾了解析性能。
enum HprofTagBytes {
  OBJECT_ID_BYTE_SIZE = 4,
  JNI_GLOBAL_REF_ID_BYTE_SIZE = 4,
  CLASS_ID_BYTE_SIZE = 4,
  CLASS_LOADER_ID_BYTE_SIZE = 4,
  INSTANCE_SIZE_BYTE_SIZE = 4,
  CONSTANT_POOL_LENGTH_BYTE_SIZE = 2,
  STATIC_FIELD_LENGTH_BYTE_SIZE = 2,
  INSTANCE_FIELD_LENGTH_BYTE_SIZE = 2,
  STACK_TRACE_SERIAL_NUMBER_BYTE_SIZE = 4,
  RECORD_TIME_BYTE_SIZE = 4,
  RECORD_LENGTH_BYTE_SIZE = 4,
  STRING_ID_BYTE_SIZE = 4,

  HEAP_TAG_BYTE_SIZE = 1,
  THREAD_SERIAL_BYTE_SIZE = 4,
  CONSTANT_POLL_INDEX_BYTE_SIZE = 2,
  BASIC_TYPE_BYTE_SIZE = 1,
  HEAP_TYPE_BYTE_SIZE = 4,
};

// 关闭详细日志：裁剪逻辑运行在write hook的热路径上，默认不打印，
// 仅在排查裁剪是否生效等问题时临时打开
#define VERBOSE_LOG false

// U4即"4字节无符号整数"的简写，对应hprof格式里object id/class id等字段的宽度，
// 用常量代替代码中反复出现的字面量4，便于表达字段语义
static constexpr int U4 = 4;

/**
 * 按hprof采用的大端(big-endian)字节序，从buf[index]起读出一个2字节短整数，
 * 用于解析常量池大小、静态/实例字段数量等u2字段。
 */
ALWAYS_INLINE int HprofStrip::GetShortFromBytes(const unsigned char *buf,
                                                int index) {
  return (buf[index] << 8u) + buf[index + 1];
}

/**
 * 按hprof采用的大端(big-endian)字节序，从buf[index]起读出一个4字节整数，
 * 用于解析实例大小、数组长度、记录长度等u4字段。
 */
ALWAYS_INLINE int HprofStrip::GetIntFromBytes(const unsigned char *buf,
                                              int index) {
  return (buf[index] << 24u) + (buf[index + 1] << 16u) +
         (buf[index + 2] << 8u) + buf[index + 3];
}

/**
 * 根据hprof基础类型编码(HprofBasicType)返回其在二进制流中占用的字节数，
 * 供解析常量池条目、静态/实例字段值、基础类型数组元素时计算需要跳过的长度，
 * 因为这些字段是变长的，必须依据类型才能正确定位下一个字段的起始位置。
 */
int HprofStrip::GetByteSizeFromType(unsigned char basic_type) {
  switch (basic_type) {
    case hprof_basic_boolean:
    case hprof_basic_byte:
      return 1;
    case hprof_basic_char:
    case hprof_basic_short:
      return 2;
    case hprof_basic_float:
    case hprof_basic_int:
    case hprof_basic_object:
      return 4;
    case hprof_basic_long:
    case hprof_basic_double:
      return 8;
    default:
      return 0;
  }
}

/**
 * 递归解析HPROF_TAG_HEAP_DUMP/HPROF_TAG_HEAP_DUMP_SEGMENT记录内的
 * 子记录(sub-record)tag流：每次读取first_index处的1字节子tag，
 * 根据子tag对应的固定/变长结构计算出该子记录的结束位置，
 * 并对zygote/image系统堆的实例、对象数组、基础类型数组等
 * 不需要保留的子记录，把其[起点,终点)区间记录到
 * strip_index_list_pair_中，最终由HookWriteInternal在写入时跳过这些区间。
 * first_index即"游标"，每处理完一个子记录就递归推进到下一个子记录起点，
 * 直到超出max_len(该heap dump记录的payload长度)为止。
 */
int HprofStrip::ProcessHeap(const void *buf, int first_index, int max_len,
                            int heap_serial_no, int array_serial_no) {
  if (first_index >= max_len) {
    return array_serial_no;
  }

  const unsigned char subtag = ((unsigned char *)buf)[first_index];
  switch (subtag) {
    /**
     * __ AddU1(heap_tag);
     * __ AddObjectId(obj);
     *
     */
    case HPROF_ROOT_UNKNOWN:
    case HPROF_ROOT_STICKY_CLASS:
    case HPROF_ROOT_MONITOR_USED:
    case HPROF_ROOT_INTERNED_STRING:
    case HPROF_ROOT_DEBUGGER:
    case HPROF_ROOT_VM_INTERNAL: {
      array_serial_no = ProcessHeap(
          buf, first_index + HEAP_TAG_BYTE_SIZE + OBJECT_ID_BYTE_SIZE, max_len,
          heap_serial_no, array_serial_no);
    } break;

    case HPROF_ROOT_JNI_GLOBAL: {
      /**
       *  __ AddU1(heap_tag);
       *  __ AddObjectId(obj);
       *  __ AddJniGlobalRefId(jni_obj);
       *
       */
      array_serial_no =
          ProcessHeap(buf,
                      first_index + HEAP_TAG_BYTE_SIZE + OBJECT_ID_BYTE_SIZE +
                          JNI_GLOBAL_REF_ID_BYTE_SIZE,
                      max_len, heap_serial_no, array_serial_no);
    } break;

      /**
       * __ AddU1(heap_tag);
       * __ AddObjectId(obj);
       * __ AddU4(thread_serial);
       * __ AddU4((uint32_t)-1);
       */
    case HPROF_ROOT_JNI_LOCAL:
    case HPROF_ROOT_JAVA_FRAME:
    case HPROF_ROOT_JNI_MONITOR: {
      array_serial_no =
          ProcessHeap(buf,
                      first_index + HEAP_TAG_BYTE_SIZE + OBJECT_ID_BYTE_SIZE +
                          THREAD_SERIAL_BYTE_SIZE + U4 /*占位*/,
                      max_len, heap_serial_no, array_serial_no);
    } break;

      /**
       * __ AddU1(heap_tag);
       * __ AddObjectId(obj);
       * __ AddU4(thread_serial);
       */
    case HPROF_ROOT_NATIVE_STACK:
    case HPROF_ROOT_THREAD_BLOCK: {
      array_serial_no =
          ProcessHeap(buf,
                      first_index + HEAP_TAG_BYTE_SIZE + OBJECT_ID_BYTE_SIZE +
                          THREAD_SERIAL_BYTE_SIZE,
                      max_len, heap_serial_no, array_serial_no);
    } break;

      /**
       * __ AddU1(heap_tag);
       * __ AddObjectId(obj);
       * __ AddU4(thread_serial);
       * __ AddU4((uint32_t)-1);    // xxx
       */
    case HPROF_ROOT_THREAD_OBJECT: {
      array_serial_no =
          ProcessHeap(buf,
                      first_index + HEAP_TAG_BYTE_SIZE + OBJECT_ID_BYTE_SIZE +
                          THREAD_SERIAL_BYTE_SIZE + U4 /*占位*/,
                      max_len, heap_serial_no, array_serial_no);
    } break;

      /**
       * __ AddU1(HPROF_CLASS_DUMP);
       * __ AddClassId(LookupClassId(klass));
       * __ AddStackTraceSerialNumber(LookupStackTraceSerialNumber(klass));
       * __ AddClassId(LookupClassId(klass->GetSuperClass().Ptr()));
       * __ AddObjectId(klass->GetClassLoader().Ptr());
       * __ AddObjectId(nullptr);    // no signer
       * __ AddObjectId(nullptr);    // no prot domain
       * __ AddObjectId(nullptr);    // reserved
       * __ AddObjectId(nullptr);    // reserved
       * __ AddU4(0); 或 __ AddU4(sizeof(mirror::String)); 或 __ AddU4(0); 或 __
       * AddU4(klass->GetObjectSize());  // instance size
       * __ AddU2(0);  // empty const pool
       * __ AddU2(dchecked_integral_cast<uint16_t>(static_fields_reported));
       * static_field_writer(class_static_field, class_static_field_name_fn);
       */
    case HPROF_CLASS_DUMP: {
      /**
       *  u2
          size of constant pool and number of records that follow:
              u2
              constant pool index
              u1
              type of entry: (See Basic Type)
              value
              value of entry (u1, u2, u4, or u8 based on type of entry)
       */
      int constant_pool_index =
          first_index + HEAP_TAG_BYTE_SIZE /*tag*/
          + CLASS_ID_BYTE_SIZE + STACK_TRACE_SERIAL_NUMBER_BYTE_SIZE +
          CLASS_ID_BYTE_SIZE /*super*/ + CLASS_LOADER_ID_BYTE_SIZE +
          OBJECT_ID_BYTE_SIZE    // Ignored: Signeres ID.
          + OBJECT_ID_BYTE_SIZE  // Ignored: Protection domain ID.
          + OBJECT_ID_BYTE_SIZE  // RESERVED.
          + OBJECT_ID_BYTE_SIZE  // RESERVED.
          + INSTANCE_SIZE_BYTE_SIZE;
      int constant_pool_size =
          GetShortFromBytes((unsigned char *)buf, constant_pool_index);
      constant_pool_index += CONSTANT_POOL_LENGTH_BYTE_SIZE;
      // 常量池条目长度依类型而变(u1/u2/u4/u8)，无法用固定偏移跳过，
      // 必须逐条读取类型再计算长度，才能定位到常量池结束、静态字段开始的位置
      for (int i = 0; i < constant_pool_size; ++i) {
        unsigned char type = ((
            unsigned char *)buf)[constant_pool_index +
                                 CONSTANT_POLL_INDEX_BYTE_SIZE /*pool index*/];
        constant_pool_index += CONSTANT_POLL_INDEX_BYTE_SIZE /*poll index*/
                               + BASIC_TYPE_BYTE_SIZE /*type*/ +
                               GetByteSizeFromType(type);
      }

      /**
       * u2 Number of static fields:
           ID
           static field name string ID
           u1
           type of field: (See Basic Type)
           value
           value of entry (u1, u2, u4, or u8 based on type of field)
       */

      int static_fields_index = constant_pool_index;
      int static_fields_size =
          GetShortFromBytes((unsigned char *)buf, static_fields_index);
      static_fields_index += STATIC_FIELD_LENGTH_BYTE_SIZE;
      // 同样因为静态字段值的长度依字段类型而定，需逐条解析类型来推进游标
      for (int i = 0; i < static_fields_size; ++i) {
        unsigned char type =
            ((unsigned char *)
                 buf)[static_fields_index + STRING_ID_BYTE_SIZE /*ID*/];
        static_fields_index += STRING_ID_BYTE_SIZE /*string ID*/ +
                               BASIC_TYPE_BYTE_SIZE /*type*/
                               + GetByteSizeFromType(type);
      }

      /**
       * u2
         Number of instance fields (not including super class's)
              ID
              field name string ID
              u1
              type of field: (See Basic Type)
       */
      int instance_fields_index = static_fields_index;
      int instance_fields_size =
          GetShortFromBytes((unsigned char *)buf, instance_fields_index);
      instance_fields_index += INSTANCE_FIELD_LENGTH_BYTE_SIZE;
      // 实例字段描述只记录"名字ID+类型"，不含值，每条长度固定，
      // 可以直接乘以字段数批量跳过，无需像常量池/静态字段那样逐条解析
      instance_fields_index +=
          (BASIC_TYPE_BYTE_SIZE + STRING_ID_BYTE_SIZE) * instance_fields_size;

      array_serial_no = ProcessHeap(buf, instance_fields_index, max_len,
                                    heap_serial_no, array_serial_no);
    }

    break;

      /**
       *__ AddU1(HPROF_INSTANCE_DUMP);
       * __ AddObjectId(obj);
       * __ AddStackTraceSerialNumber(LookupStackTraceSerialNumber(obj));
       * __ AddClassId(LookupClassId(klass));
       *
       * __ AddU4(0x77777777);//length
       *
       * ***
       */
    case HPROF_INSTANCE_DUMP: {
      int instance_dump_index =
          first_index + HEAP_TAG_BYTE_SIZE + OBJECT_ID_BYTE_SIZE +
          STACK_TRACE_SERIAL_NUMBER_BYTE_SIZE + CLASS_ID_BYTE_SIZE;
      int instance_size =
          GetIntFromBytes((unsigned char *)buf, instance_dump_index);

      // 裁剪掉system space
      if (is_current_system_heap_) {
        strip_index_list_pair_[strip_index_ * 2] = first_index;
        strip_index_list_pair_[strip_index_ * 2 + 1] =
            instance_dump_index + U4 /*占位*/ + instance_size;
        strip_index_++;

        strip_bytes_sum_ +=
            instance_dump_index + U4 /*占位*/ + instance_size - first_index;
      }

      array_serial_no =
          ProcessHeap(buf, instance_dump_index + U4 /*占位*/ + instance_size,
                      max_len, heap_serial_no, array_serial_no);
    } break;

      /**
       * __ AddU1(HPROF_OBJECT_ARRAY_DUMP);
       * __ AddObjectId(obj);
       * __ AddStackTraceSerialNumber(LookupStackTraceSerialNumber(obj));
       * __ AddU4(length);
       * __ AddClassId(LookupClassId(klass));
       *
       * // Dump the elements, which are always objects or null.
       * __ AddIdList(obj->AsObjectArray<mirror::Object>().Ptr());
       */
    case HPROF_OBJECT_ARRAY_DUMP: {
      int length = GetIntFromBytes((unsigned char *)buf,
                                   first_index + HEAP_TAG_BYTE_SIZE +
                                       OBJECT_ID_BYTE_SIZE +
                                       STACK_TRACE_SERIAL_NUMBER_BYTE_SIZE);

      // 裁剪掉system space
      if (is_current_system_heap_) {
        strip_index_list_pair_[strip_index_ * 2] = first_index;
        strip_index_list_pair_[strip_index_ * 2 + 1] =
            first_index + HEAP_TAG_BYTE_SIZE + OBJECT_ID_BYTE_SIZE +
            STACK_TRACE_SERIAL_NUMBER_BYTE_SIZE + U4 /*Length*/
            + CLASS_ID_BYTE_SIZE + U4 /*Id*/ * length;
        strip_index_++;

        strip_bytes_sum_ += HEAP_TAG_BYTE_SIZE + OBJECT_ID_BYTE_SIZE +
                            STACK_TRACE_SERIAL_NUMBER_BYTE_SIZE + U4 /*Length*/
                            + CLASS_ID_BYTE_SIZE + U4 /*Id*/ * length;
      }

      array_serial_no =
          ProcessHeap(buf,
                      first_index + HEAP_TAG_BYTE_SIZE + OBJECT_ID_BYTE_SIZE +
                          STACK_TRACE_SERIAL_NUMBER_BYTE_SIZE + U4 /*Length*/
                          + CLASS_ID_BYTE_SIZE + U4 /*Id*/ * length,
                      max_len, heap_serial_no, array_serial_no);
    } break;

      /**
       *
       * __ AddU1(HPROF_PRIMITIVE_ARRAY_DUMP);
       * __ AddClassStaticsId(klass);
       * __ AddStackTraceSerialNumber(LookupStackTraceSerialNumber(klass));
       * __ AddU4(java_heap_overhead_size - 4);
       * __ AddU1(hprof_basic_byte);
       * for (size_t i = 0; i < java_heap_overhead_size - 4; ++i) {
       *      __ AddU1(0);
       * }
       *
       * // obj is a primitive array.
       * __ AddU1(HPROF_PRIMITIVE_ARRAY_DUMP);
       * __ AddObjectId(obj);
       * __ AddStackTraceSerialNumber(LookupStackTraceSerialNumber(obj));
       * __ AddU4(length);
       * __ AddU1(t);
       * // Dump the raw, packed element values.
       * if (size == 1) {
       *      __ AddU1List(reinterpret_cast<const
       * uint8_t*>(obj->GetRawData(sizeof(uint8_t), 0)), length); } else if
       * (size == 2) {
       *      __ AddU2List(reinterpret_cast<const
       * uint16_t*>(obj->GetRawData(sizeof(uint16_t), 0)), length); } else if
       * (size == 4) {
       *      __ AddU4List(reinterpret_cast<const
       * uint32_t*>(obj->GetRawData(sizeof(uint32_t), 0)), length); } else if
       * (size == 8) {
       *      __ AddU8List(reinterpret_cast<const
       * uint64_t*>(obj->GetRawData(sizeof(uint64_t), 0)), length);
       * }
       */
    case HPROF_PRIMITIVE_ARRAY_DUMP: {
      int primitive_array_dump_index = first_index + HEAP_TAG_BYTE_SIZE /*tag*/
                                       + OBJECT_ID_BYTE_SIZE +
                                       STACK_TRACE_SERIAL_NUMBER_BYTE_SIZE;
      int length =
          GetIntFromBytes((unsigned char *)buf, primitive_array_dump_index);
      primitive_array_dump_index += U4 /*Length*/;

      // 裁剪掉基本类型数组，无论是否在system space都进行裁剪
      // 区别是数组左坐标，app space时带数组元信息（类型、长度）方便回填
      if (is_current_system_heap_) {
        strip_index_list_pair_[strip_index_ * 2] = first_index;
      } else {
        strip_index_list_pair_[strip_index_ * 2] =
            primitive_array_dump_index + BASIC_TYPE_BYTE_SIZE /*value type*/;
      }
      array_serial_no++;

      int value_size = GetByteSizeFromType(
          ((unsigned char *)buf)[primitive_array_dump_index]);
      primitive_array_dump_index +=
          BASIC_TYPE_BYTE_SIZE /*value type*/ + value_size * length;

      // 数组右坐标
      strip_index_list_pair_[strip_index_ * 2 + 1] = primitive_array_dump_index;

      // app space时，不修改长度因为回填数组时会补齐
      if (is_current_system_heap_) {
        strip_bytes_sum_ += primitive_array_dump_index - first_index;
      }
      strip_index_++;

      array_serial_no = ProcessHeap(buf, primitive_array_dump_index, max_len,
                                    heap_serial_no, array_serial_no);
    } break;

      // Android.
    case HPROF_HEAP_DUMP_INFO: {
      const unsigned char heap_type =
          ((unsigned char *)buf)[first_index + HEAP_TAG_BYTE_SIZE + 3];
      is_current_system_heap_ =
          (heap_type == HPROF_HEAP_ZYGOTE || heap_type == HPROF_HEAP_IMAGE);

      if (is_current_system_heap_) {
        strip_index_list_pair_[strip_index_ * 2] = first_index;
        strip_index_list_pair_[strip_index_ * 2 + 1] =
            first_index + HEAP_TAG_BYTE_SIZE /*TAG*/
            + HEAP_TYPE_BYTE_SIZE            /*heap type*/
            + STRING_ID_BYTE_SIZE /*string id*/;
        strip_index_++;
        strip_bytes_sum_ += HEAP_TAG_BYTE_SIZE    /*TAG*/
                            + HEAP_TYPE_BYTE_SIZE /*heap type*/
                            + STRING_ID_BYTE_SIZE /*string id*/;
      }

      array_serial_no = ProcessHeap(buf,
                                    first_index + HEAP_TAG_BYTE_SIZE /*TAG*/
                                        + HEAP_TYPE_BYTE_SIZE /*heap type*/
                                        + STRING_ID_BYTE_SIZE /*string id*/,
                                    max_len, heap_serial_no, array_serial_no);
    } break;

    case HPROF_ROOT_FINALIZING:                // Obsolete.
    case HPROF_ROOT_REFERENCE_CLEANUP:         // Obsolete.
    case HPROF_UNREACHABLE:                    // Obsolete.
    case HPROF_PRIMITIVE_ARRAY_NODATA_DUMP: {  // Obsolete.
      array_serial_no = ProcessHeap(buf, first_index + HEAP_TAG_BYTE_SIZE,
                                    max_len, heap_serial_no, array_serial_no);
    } break;

    default:
      break;
  }
  return array_serial_no;
}

/**
 * xhook注册的open替身函数：所有被hook到的libart/libbase/libartbase中的open调用
 * 都会先落到这里，再转发给单例的HookOpenInternal处理，
 * 因为xhook要求hook替身是普通C风格函数，无法直接指向类成员函数。
 */
static int HookOpen(const char *pathname, int flags, ...) {
  va_list ap;
  va_start(ap, flags);
  int fd = HprofStrip::GetInstance().HookOpenInternal(pathname, flags, ap);
  va_end(ap);
  return fd;
}

/**
 * open调用被拦截后的真正处理逻辑：先照常放行调用拿到真实fd，
 * 再判断本次打开的文件名是否命中目标hprof文件名，
 * 只有匹配上才记录该fd，后续write时才需要按fd过滤做裁剪，
 * 避免误伤进程内其他文件的正常读写。
 */
int HprofStrip::HookOpenInternal(const char *path_name, int flags, ...) {
  va_list ap;
  va_start(ap, flags);
  // 调用真正的open系统调用完成文件打开，本类只是在旁路观察fd与路径的对应关系，
  // 不能改变原有的打开行为
  int fd = open(path_name, flags, ap);
  va_end(ap);

  if (hprof_name_.empty()) {
    return fd;
  }

  // 通过路径中是否包含目标hprof文件名，将系统分配的fd与"这是不是hprof文件"关联起来，
  // 因为open本身不知道调用方语义，只能靠文件名匹配还原出这层信息
  if (path_name != nullptr && strstr(path_name, hprof_name_.c_str())) {
    hprof_fd_ = fd;
    is_hook_success_ = true;
  }
  return fd;
}

/**
 * xhook注册的write替身函数：所有被hook到的libc/libart/libbase/libartbase中
 * 的write调用都会先落到这里，再转发给单例的HookWriteInternal处理。
 */
static ssize_t HookWrite(int fd, const void *buf, size_t count) {
  return HprofStrip::GetInstance().HookWriteInternal(fd, buf, count);
}

/**
 * 每次拦截到一次针对目标hprof fd的write调用前，
 * 清空上一次计算出的裁剪区间数量与累计裁剪字节数，避免状态串到本次写入中。
 */
void HprofStrip::reset() {
  strip_index_ = 0;
  strip_bytes_sum_ = 0;
}

/**
 * 保证count字节全部写入fd：POSIX的write系统调用允许"部分写入"，
 * 一次调用可能只写入了部分请求的字节数，因此需要循环补写剩余部分，
 * 否则裁剪后的hprof数据可能被截断，导致下游解析工具读到不完整文件。
 */
size_t HprofStrip::FullyWrite(int fd, const void *buf, ssize_t count) {
  size_t left = count;
  while (left > 0) {
    // 每轮从buf中尚未写完的偏移处继续写入剩余left字节
    ssize_t written = write(fd, (unsigned char*)buf + (count - left), left);
    if (written != -1) left -= written;
  }
  return count;
}

/**
 * write调用被拦截后的真正处理逻辑：非目标hprof fd的写入原样透传，
 * 只有命中hprof_fd_的写入才会被解析、裁剪后再落盘，
 * 这样可以在dump过程中"边写边裁"，不需要事后再对整个hprof文件做二次改写。
 */
ssize_t HprofStrip::HookWriteInternal(int fd, const void *buf, ssize_t count) {
  if (fd != hprof_fd_) {
    // 非hprof文件的写入不做任何拦截处理，直接调用真正的write系统调用完成
    return write(fd, buf, count);
  }

  // 每次hook_write，初始化重置
  reset();

  // buf[0]即本条hprof记录的顶层tag(见HprofTag枚举)，一次write调用对应一条完整的hprof记录
  const unsigned char tag = ((unsigned char *)buf)[0];
  // 删除掉无关record tag类型匹配，只匹配heap相关提高性能
  switch (tag) {
    case HPROF_TAG_HEAP_DUMP:
    case HPROF_TAG_HEAP_DUMP_SEGMENT: {
      // 跳过tag(1字节)+时间戳(4字节)+记录长度(4字节)这段记录头，
      // 从heap dump的payload起点开始递归解析其内部的子记录tag流
      ProcessHeap(
          buf,
          HEAP_TAG_BYTE_SIZE + RECORD_TIME_BYTE_SIZE + RECORD_LENGTH_BYTE_SIZE,
          count, heap_serial_num_, 0);
      heap_serial_num_++;
    } break;
    default:
      break;
  }

  // 根据裁剪掉的zygote space和image space更新length
  int record_length;
  if (tag == HPROF_TAG_HEAP_DUMP || tag == HPROF_TAG_HEAP_DUMP_SEGMENT) {
    record_length = GetIntFromBytes((unsigned char *)buf,
                                    HEAP_TAG_BYTE_SIZE + RECORD_TIME_BYTE_SIZE);
    record_length -= strip_bytes_sum_;
    int index = HEAP_TAG_BYTE_SIZE + RECORD_TIME_BYTE_SIZE;
    // 必须把裁剪后的真实长度写回记录头的length字段(按大端逐字节回填)，
    // 否则hprof分析工具会按原始长度去读取payload，读到裁剪造成的数据错位
    ((unsigned char *)buf)[index] =
        (unsigned char)(((unsigned int)record_length & 0xff000000u) >> 24u);
    ((unsigned char *)buf)[index + 1] =
        (unsigned char)(((unsigned int)record_length & 0x00ff0000u) >> 16u);
    ((unsigned char *)buf)[index + 2] =
        (unsigned char)(((unsigned int)record_length & 0x0000ff00u) >> 8u);
    ((unsigned char *)buf)[index + 3] =
        (unsigned char)((unsigned int)record_length & 0x000000ffu);
  }

  size_t total_write = 0;
  int start_index = 0;
  // 按裁剪区间对buf做"分段写入"：每次只写strip_index_list_pair_标记的
  // 裁剪区间之前保留下来的那一段，从而跳过被裁剪的字节，
  // 无需为此额外分配缓冲区拷贝出一份"去掉裁剪内容"的新数据
  for (int i = 0; i < strip_index_; i++) {
    // 将裁剪掉的区间，通过写时过滤掉
    void *write_buf = (void *)((unsigned char *)buf + start_index);
    auto write_len = (size_t)(strip_index_list_pair_[i * 2] - start_index);
    if (write_len > 0) {
      total_write += FullyWrite(fd, write_buf, write_len);
    } else if (write_len < 0) {
      __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                          "HookWrite array i:%d writeLen<0:%zu", i, write_len);
    }
    start_index = strip_index_list_pair_[i * 2 + 1];
  }
  auto write_len = (size_t)(count - start_index);
  if (write_len > 0) {
    void *write_buf = (void *)((unsigned char *)buf + start_index);
    total_write += FullyWrite(fd, write_buf, count - start_index);
  }

  hook_write_serial_num_++;

  if (VERBOSE_LOG && total_write != count) {
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                        "hook write, hprof strip happens");
  }

  return count;
}

/**
 * 通过xhook对多个so中的open/write符号做PLT/GOT hook注册，
 * 使ART虚拟机在dump hprof时实际调用到的open/write都会先经过
 * HookOpen/HookWrite转发到本类，从而获得裁剪时机。
 * 之所以要注册这么多份，是因为同一个符号在不同Android版本上
 * 实际实现所在的so不同，需要逐个尝试才能覆盖所有机型版本。
 */
void HprofStrip::HookInit() {
  // 关闭xhook自身的调试日志，避免线上噪音
  xhook_enable_debug(0);
  /**
   *
   * android 7.x，write方法在libc.so中
   * android 8-9，write方法在libart.so中
   * android 10，write方法在libartbase.so中
   * libbase.so是一个保险操作，防止前面2个so里面都hook不到(:
   *
   * android 7-10版本，open方法都在libart.so中
   * libbase.so与libartbase.so，为保险操作
   */
  xhook_register("libart.so", "open", (void *)HookOpen, nullptr);
  xhook_register("libbase.so", "open", (void *)HookOpen, nullptr);
  xhook_register("libartbase.so", "open", (void *)HookOpen, nullptr);

  xhook_register("libc.so", "write", (void *)HookWrite, nullptr);
  xhook_register("libart.so", "write", (void *)HookWrite, nullptr);
  xhook_register("libbase.so", "write", (void *)HookWrite, nullptr);
  xhook_register("libartbase.so", "write", (void *)HookWrite, nullptr);

  // 将上面register的hook表实际应用到已加载so的GOT/PLT表项上，
  // 之后这些so内对open/write的调用才会真正跳转到HookOpen/HookWrite
  xhook_refresh(0);
  // 清理xhook内部为本次注册维护的临时数据，释放内存
  xhook_clear();
}

/**
 * 获取HprofStrip的全局唯一实例。
 * 使用函数内static局部变量实现懒汉式单例，保证首次调用时才构造，
 * 且在C++11后线程安全，供open/write的hook替身函数转发调用。
 */
HprofStrip &HprofStrip::GetInstance() {
  static HprofStrip hprof_strip;
  return hprof_strip;
}

/**
 * 构造函数：将本次dump相关的状态清零/复位，
 * 并把裁剪区间数组清零，确保每次进程fork出来dump时都是干净的初始状态。
 */
HprofStrip::HprofStrip()
    : hprof_fd_(-1),
      strip_bytes_sum_(0),
      heap_serial_num_(0),
      hook_write_serial_num_(0),
      strip_index_(0),
      is_hook_success_(false),
      is_current_system_heap_(false) {
  // strip_index_list_pair_体积较大(约512KB)，作为成员数组只需要在构造时清零一次，
  // 避免在处于hook回调热路径的ProcessHeap/HookWriteInternal中反复做动态分配
  std::fill(strip_index_list_pair_,
            strip_index_list_pair_ + arraysize(strip_index_list_pair_), 0);
}

/**
 * 记录Kotlin层生成的目标hprof文件名，供HookOpenInternal匹配文件路径时使用。
 */
void HprofStrip::SetHprofName(const char *hprof_name) {
  hprof_name_ = hprof_name;
}

}  // namespace leak_monitor
}  // namespace kwai