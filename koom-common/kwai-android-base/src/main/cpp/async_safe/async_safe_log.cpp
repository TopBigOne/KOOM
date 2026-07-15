/*
 * Copyright (C) 2010 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/net.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <android/set_abort_message.h>
#include <async_safe/log.h>
#include <bionic/ndk_port.h>
#include <kwai_util/kwai_macros.h>

#include "private/CachedProperty.h"
#include "private/ErrnoRestorer.h"
#include "private/ScopedPthreadMutexLocker.h"

// Don't call libc's close or socket, since it might call back into us as a result of fdsan/fdtrack.
// More generally, this whole file avoids libc/Android log wrapper functions (which may
// call malloc() internally) and instead issues raw syscall() directly. That matters
// because this logging path can be invoked from within a signal handler (e.g. crash/
// ANR dumping): if the signal arrived while the interrupted code already held libc's
// malloc lock, any malloc() call made from the handler would deadlock the process.
// Raw syscalls never touch the heap, so they're async-signal-safe by construction.
// 中文：更概括地说，本文件全程避免使用 libc/Android 的日志封装函数（它们内部可能
// 调用 malloc()），而是直接发起原始 syscall()。这一点很重要，因为这条日志路径可能
// 在信号处理函数中被调用（例如崩溃/ANR 转储场景）：如果信号到达时被打断的代码恰好
// 持有 libc 的 malloc 锁，那么处理函数中任何 malloc() 调用都会导致进程死锁。
// 原始系统调用不会触碰堆内存，因此天然满足异步信号安全（async-signal-safe）。
#pragma GCC poison close
// syscall(__NR_close, ...) bypasses libc's close() (and fdsan's tracking around it)
// entirely - guarantees no allocation and no fdsan callback re-entrancy.
// 中文：syscall(__NR_close, ...) 完全绕过了 libc 的 close()（以及其 fdsan 追踪逻辑），
// 保证不会发生内存分配，也不会触发 fdsan 回调重入。
static int __close(int fd) { return syscall(__NR_close, fd); }

// syscall(__NR_socket, ...) / SYS_SOCKET bypasses libc's socket() the same way __close
// bypasses close() above - keeps this async-signal-safe logging path malloc-free.
// 中文：syscall(__NR_socket, ...) / SYS_SOCKET 与上面 __close 绕过 close() 的方式相同，
// 用来绕过 libc 的 socket()，从而保持这条异步信号安全的日志路径不涉及 malloc。
static int __socket(int domain, int type, int protocol) {
#if defined(__i386__)
  unsigned long args[3] = {static_cast<unsigned long>(domain), static_cast<unsigned long>(type),
                           static_cast<unsigned long>(protocol)};
  return syscall(__NR_socketcall, SYS_SOCKET, &args);
#else
  return syscall(__NR_socket, domain, type, protocol);
#endif
}

// Must be kept in sync with frameworks/base/core/java/android/util/EventLog.java.
enum AndroidEventLogType {
  EVENT_TYPE_INT = 0,
  EVENT_TYPE_LONG = 1,
  EVENT_TYPE_STRING = 2,
  EVENT_TYPE_LIST = 3,
  EVENT_TYPE_FLOAT = 4,
};

/**
 * Output sink for out_vformat() that writes formatted text into a fixed-size caller
 * buffer instead of allocating - no malloc means this stays safe to use from a
 * signal handler (see the async-signal-safety note near __close()/__socket() above).
 *
 * 中文：out_vformat() 使用的一种输出目标，将格式化文本写入调用方提供的固定大小
 * 缓冲区，而不是动态分配内存；没有 malloc 意味着它可以安全地在信号处理函数中
 * 使用（参见上文 __close()/__socket() 附近关于异步信号安全的说明）。
 */
struct BufferOutputStream {
public:
  BufferOutputStream(char *buffer, size_t size) : total(0), pos_(buffer), avail_(size) {
    if (avail_ > 0)
      pos_[0] = '\0';
  }
  ~BufferOutputStream() = default;

  void Send(const char *data, int len) {
    if (len < 0) {
      len = strlen(data);
    }
    total += len;

    if (avail_ <= 1) {
      // No space to put anything else.
      return;
    }

    if (static_cast<size_t>(len) >= avail_) {
      len = avail_ - 1;
    }
    memcpy(pos_, data, len);
    pos_ += len;
    pos_[0] = '\0';
    avail_ -= len;
  }

  size_t total;

private:
  char *pos_;
  size_t avail_;
};

/**
 * Output sink for out_vformat() that streams formatted text directly to a raw fd via
 * write() (retried on EINTR), with no intermediate heap buffer - keeps the formatter
 * usable from async-signal context the same way BufferOutputStream does.
 *
 * 中文：out_vformat() 使用的另一种输出目标，通过 write()（遇到 EINTR 时重试）将
 * 格式化文本直接写入原始文件描述符，中间不经过任何堆缓冲区；与 BufferOutputStream
 * 一样，使这个格式化器可以在异步信号上下文中使用。
 */
struct FdOutputStream {
public:
  explicit FdOutputStream(int fd) : total(0), fd_(fd) {}

  void Send(const char *data, int len) {
    if (len < 0) {
      len = strlen(data);
    }
    total += len;

    while (len > 0) {
      ssize_t bytes = TEMP_FAILURE_RETRY(write(fd_, data, len));
      if (bytes == -1) {
        return;
      }
      data += bytes;
      len -= bytes;
    }
  }

  size_t total;

private:
  int fd_;
};

/*** formatted output implementation
 ***/

/* Parse a decimal string from 'format + *ppos',
 * return the value, and writes the new position past
 * the decimal string in '*ppos' on exit.
 *
 * NOTE: Does *not* handle a sign prefix.
 */
static unsigned parse_decimal(const char *format, int *ppos) {
  const char *p = format + *ppos;
  unsigned result = 0;

  for (;;) {
    int ch = *p;
    unsigned d = static_cast<unsigned>(ch - '0');

    if (d >= 10U) {
      break;
    }

    result = result * 10 + d;
    p++;
  }
  *ppos = p - format;
  return result;
}

// Writes number 'value' in base 'base' into buffer 'buf' of size 'buf_size' bytes.
// Assumes that buf_size > 0.
static void format_unsigned(char *buf, size_t buf_size, uint64_t value, int base, bool caps) {
  char *p = buf;
  char *end = buf + buf_size - 1;

  // Generate digit string in reverse order.
  while (value) {
    unsigned d = value % base;
    value /= base;
    if (p != end) {
      char ch;
      if (d < 10) {
        ch = '0' + d;
      } else {
        ch = (caps ? 'A' : 'a') + (d - 10);
      }
      *p++ = ch;
    }
  }

  // Special case for 0.
  if (p == buf) {
    if (p != end) {
      *p++ = '0';
    }
  }
  *p = '\0';

  // Reverse digit string in-place.
  size_t length = p - buf;
  for (size_t i = 0, j = length - 1; i < j; ++i, --j) {
    char ch = buf[i];
    buf[i] = buf[j];
    buf[j] = ch;
  }
}

static void format_integer(char *buf, size_t buf_size, uint64_t value, char conversion) {
  // Decode the conversion specifier.
  int is_signed = (conversion == 'd' || conversion == 'i' || conversion == 'o');
  int base = 10;
  if (conversion == 'x' || conversion == 'X') {
    base = 16;
  } else if (conversion == 'o') {
    base = 8;
  }
  bool caps = (conversion == 'X');

  if (is_signed && static_cast<int64_t>(value) < 0) {
    buf[0] = '-';
    buf += 1;
    buf_size -= 1;
    value = static_cast<uint64_t>(-static_cast<int64_t>(value));
  }
  format_unsigned(buf, buf_size, value, base, caps);
}

template <typename Out> static void SendRepeat(Out &o, char ch, int count) {
  char pad[8];
  memset(pad, ch, sizeof(pad));

  const int pad_size = static_cast<int>(sizeof(pad));
  while (count > 0) {
    int avail = count;
    if (avail > pad_size) {
      avail = pad_size;
    }
    o.Send(pad, avail);
    count -= avail;
  }
}

/**
 * A minimal, allocation-free printf-style formatter (subset of conversions: %s %c %p
 * %d %i %o %u %x %X %%, plus width/zero-pad/left-align). Exists because the real
 * libc/Android vsnprintf-family functions are not guaranteed async-signal-safe (they
 * may allocate), so this hand-rolled implementation is used instead wherever logging
 * needs to work from inside a signal handler.
 *
 * 中文：一个极简、不分配内存的 printf 风格格式化器（支持部分转换说明符：%s %c %p
 * %d %i %o %u %x %X %%，以及宽度/补零/左对齐）。之所以存在，是因为真正的
 * libc/Android vsnprintf 系列函数并不保证异步信号安全（它们内部可能分配内存），
 * 所以在需要于信号处理函数内部进行日志格式化的地方，改用这个手写实现代替。
 */
/* Perform formatted output to an output target 'o' */
template <typename Out> static void out_vformat(Out &o, const char *format, va_list args) {
  int nn = 0;

  for (;;) {
    int mm;
    int padZero = 0;
    int padLeft = 0;
    char sign = '\0';
    int width = -1;
    int prec = -1;
    size_t bytelen = sizeof(int);
    int slen;
    char buffer[32]; /* temporary buffer used to format numbers */

    char c;

    /* first, find all characters that are not 0 or '%' */
    /* then send them to the output directly */
    mm = nn;
    do {
      c = format[mm];
      if (c == '\0' || c == '%')
        break;
      mm++;
    } while (1);

    if (mm > nn) {
      o.Send(format + nn, mm - nn);
      nn = mm;
    }

    /* is this it ? then exit */
    if (c == '\0')
      break;

    /* nope, we are at a '%' modifier */
    nn++; // skip it

    /* parse flags */
    for (;;) {
      c = format[nn++];
      if (c == '\0') { /* single trailing '%' ? */
        c = '%';
        o.Send(&c, 1);
        return;
      } else if (c == '0') {
        padZero = 1;
        continue;
      } else if (c == '-') {
        padLeft = 1;
        continue;
      } else if (c == ' ' || c == '+') {
        sign = c;
        continue;
      }
      break;
    }

    /* parse field width */
    if ((c >= '0' && c <= '9')) {
      nn--;
      width = static_cast<int>(parse_decimal(format, &nn));
      c = format[nn++];
    }

    /* parse precision */
    if (c == '.') {
      prec = static_cast<int>(parse_decimal(format, &nn));
      c = format[nn++];
    }

    /* length modifier */
    switch (c) {
    case 'h':
      bytelen = sizeof(short);
      if (format[nn] == 'h') {
        bytelen = sizeof(char);
        nn += 1;
      }
      c = format[nn++];
      break;
    case 'l':
      bytelen = sizeof(long);
      if (format[nn] == 'l') {
        bytelen = sizeof(long long);
        nn += 1;
      }
      c = format[nn++];
      break;
    case 'z':
      bytelen = sizeof(size_t);
      c = format[nn++];
      break;
    case 't':
      bytelen = sizeof(ptrdiff_t);
      c = format[nn++];
      break;
    default:;
    }

    /* conversion specifier */
    const char *str = buffer;
    if (c == 's') {
      /* string */
      str = va_arg(args, const char *);
      if (str == nullptr) {
        str = "(null)";
      }
    } else if (c == 'c') {
      /* character */
      /* NOTE: char is promoted to int when passed through the stack */
      buffer[0] = static_cast<char>(va_arg(args, int));
      buffer[1] = '\0';
    } else if (c == 'p') {
      uint64_t value = reinterpret_cast<uintptr_t>(va_arg(args, void *));
      buffer[0] = '0';
      buffer[1] = 'x';
      format_integer(buffer + 2, sizeof(buffer) - 2, value, 'x');
    } else if (c == 'd' || c == 'i' || c == 'o' || c == 'u' || c == 'x' || c == 'X') {
      /* integers - first read value from stack */
      uint64_t value;
      int is_signed = (c == 'd' || c == 'i' || c == 'o');

      /* NOTE: int8_t and int16_t are promoted to int when passed
       *       through the stack
       */
      switch (bytelen) {
      case 1:
        value = static_cast<uint8_t>(va_arg(args, int));
        break;
      case 2:
        value = static_cast<uint16_t>(va_arg(args, int));
        break;
      case 4:
        value = va_arg(args, uint32_t);
        break;
      case 8:
        value = va_arg(args, uint64_t);
        break;
      default:
        return; /* should not happen */
      }

      /* sign extension, if needed */
      if (is_signed) {
        int shift = 64 - 8 * bytelen;
        value = static_cast<uint64_t>((static_cast<int64_t>(value << shift)) >> shift);
      }

      /* format the number properly into our buffer */
      format_integer(buffer, sizeof(buffer), value, c);
    } else if (c == '%') {
      buffer[0] = '%';
      buffer[1] = '\0';
    } else {
      __assert(__FILE__, __LINE__, "conversion specifier unsupported");
    }

    /* if we are here, 'str' points to the content that must be
     * outputted. handle padding and alignment now */

    slen = strlen(str);

    if (sign != '\0' || prec != -1) {
      __assert(__FILE__, __LINE__, "sign/precision unsupported");
    }

    if (slen < width && !padLeft) {
      char padChar = padZero ? '0' : ' ';
      SendRepeat(o, padChar, width - slen);
    }

    o.Send(str, slen);

    if (slen < width && padLeft) {
      char padChar = padZero ? '0' : ' ';
      SendRepeat(o, padChar, width - slen);
    }
  }
}

/**
 * Async-signal-safe alternative to vsnprintf(): formats into |buffer| via
 * out_vformat()/BufferOutputStream, never touching the heap.
 *
 * 中文：vsnprintf() 的异步信号安全替代方案：通过 out_vformat()/BufferOutputStream
 * 将结果格式化写入 |buffer|，全程不触碰堆内存。
 */
int async_safe_format_buffer_va_list(char *buffer, size_t buffer_size, const char *format,
                                     va_list args) {
  BufferOutputStream os(buffer, buffer_size);
  out_vformat(os, format, args);
  return os.total;
}

/**
 * Varargs convenience wrapper around async_safe_format_buffer_va_list().
 *
 * 中文：async_safe_format_buffer_va_list() 的可变参数（varargs）便捷封装。
 */
int async_safe_format_buffer(char *buffer, size_t buffer_size, const char *format, ...) {
  va_list args;
  va_start(args, format);
  int buffer_len = async_safe_format_buffer_va_list(buffer, buffer_size, format, args);
  va_end(args);
  return buffer_len;
}

/**
 * Async-signal-safe formatted write straight to a raw fd via out_vformat()/
 * FdOutputStream, with no intermediate heap buffer.
 *
 * 中文：异步信号安全的格式化写入函数，通过 out_vformat()/FdOutputStream 直接写入
 * 原始文件描述符，中间不经过任何堆缓冲区。
 */
int async_safe_format_fd_va_list(int fd, const char *format, va_list args) {
  FdOutputStream os(fd);
  out_vformat(os, format, args);
  return os.total;
}

/**
 * Varargs convenience wrapper around async_safe_format_fd_va_list().
 *
 * 中文：async_safe_format_fd_va_list() 的可变参数（varargs）便捷封装。
 */
int async_safe_format_fd(int fd, const char *format, ...) {
  va_list args;
  va_start(args, format);
  int result = async_safe_format_fd_va_list(fd, format, args);
  va_end(args);
  return result;
}

/**
 * Fallback path used when talking to logd over its socket fails (open_log_socket()
 * below): write "tag: msg\n" straight to stderr's fd instead.
 *
 * 中文：当通过 socket 与 logd 通信失败时（见下方 open_log_socket()）使用的兜底
 * 路径：改为直接把 "tag: msg\n" 写到 stderr 的文件描述符上。
 */
static int write_stderr(int priority, const char *tag, const char *msg) {
  static int api_level = android_get_device_api_level();
  if (api_level < __ANDROID_API_L__) {
    __android_log_write(priority, tag, msg);
  }
  iovec vec[4];
  vec[0].iov_base = const_cast<char *>(tag);
  vec[0].iov_len = strlen(tag);
  vec[1].iov_base = const_cast<char *>(": ");
  vec[1].iov_len = 2;
  vec[2].iov_base = const_cast<char *>(msg);
  vec[2].iov_len = strlen(msg);
  vec[3].iov_base = const_cast<char *>("\n");
  vec[3].iov_len = 1;

  // writev() gathers the tag/": "/msg/"\n" pieces into one syscall instead of several
  // write() calls or any libc formatted-print helper - vectors are pre-built above,
  // no allocation is performed here.
  // 中文：writev() 把 tag / ": " / msg / "\n" 这几段数据聚合成一次系统调用写出，
  // 而不是多次 write() 调用或使用任何 libc 格式化打印辅助函数；上面已经预先构建好
  // 了各个 iovec，这里不会发生内存分配。
  int result = TEMP_FAILURE_RETRY(writev(STDERR_FILENO, vec, 4));
  return result;
}

/**
 * Open a UNIX datagram socket connected to logd's write endpoint
 * (/dev/socket/logdw), using only raw syscalls (__socket/connect) so this can run
 * from a signal handler without risking a malloc-related deadlock.
 *
 * 中文：打开一个连接到 logd 写入端点（/dev/socket/logdw）的 UNIX 数据报 socket，
 * 全程只使用原始系统调用（__socket/connect），使其可以在信号处理函数中运行而
 * 不会有因 malloc 导致死锁的风险。
 */
static int open_log_socket() {
  // ToDo: Ideally we want this to fail if the gid of the current
  // process is AID_LOGD, but will have to wait until we have
  // registered this in private/android_filesystem_config.h. We have
  // found that all logd crashes thus far have had no problem stuffing
  // the UNIX domain socket and moving on so not critical *today*.

  // __socket() (raw syscall, not libc socket()) avoids fdsan/fdtrack callbacks and any
  // hidden allocation - see the async-signal-safety note near the top of this file.
  // 中文：__socket()（原始系统调用，而非 libc 的 socket()）避免了 fdsan/fdtrack
  // 回调以及任何隐藏的内存分配——参见文件顶部关于异步信号安全的说明。
  int log_fd = TEMP_FAILURE_RETRY(__socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  if (log_fd == -1) {
    return -1;
  }

  union {
    struct sockaddr addr;
    struct sockaddr_un addrUn;
  } u;
  memset(&u, 0, sizeof(u));
  u.addrUn.sun_family = AF_UNIX;
  strlcpy(u.addrUn.sun_path, "/dev/socket/logdw", sizeof(u.addrUn.sun_path));

  // connect() here is still safe to call directly (unlike close/socket, libc's
  // connect() isn't poisoned/wrapped) and binds this datagram socket to logd.
  // 中文：这里直接调用 connect() 仍然是安全的（不同于 close/socket，libc 的
  // connect() 并没有被 poison/封装），用来把这个数据报 socket 绑定到 logd。
  if (TEMP_FAILURE_RETRY(connect(log_fd, &u.addr, sizeof(u.addrUn))) != 0) {
    __close(log_fd);
    return -1;
  }

  return log_fd;
}

struct log_time { // Wire format
  uint32_t tv_sec;
  uint32_t tv_nsec;
};

/**
 * Build logd's wire-format log entry (log id, tid, timestamp, priority, tag, msg) and
 * send it over the socket from open_log_socket(), falling back to stderr on failure.
 * Every step here uses only raw syscalls/no-alloc helpers so it remains safe to call
 * from a signal handler (see the async-signal-safety note near the top of this file).
 *
 * 中文：构建 logd 线路格式（wire-format）的日志条目（log id、tid、时间戳、优先级、
 * tag、msg），并通过 open_log_socket() 打开的 socket 发送出去；失败时回退到写
 * stderr。这里每一步都只使用原始系统调用/不分配内存的辅助函数，因此仍可安全地
 * 在信号处理函数中调用（参见文件顶部关于异步信号安全的说明）。
 */
int async_safe_write_log(int priority, const char *tag, const char *msg) {
  int main_log_fd = open_log_socket();
  if (main_log_fd == -1) {
    // Try stderr instead.
    return write_stderr(priority, tag, msg);
  }

  iovec vec[6];
  char log_id = (priority == ANDROID_LOG_FATAL) ? LOG_ID_CRASH : LOG_ID_MAIN;
  vec[0].iov_base = &log_id;
  vec[0].iov_len = sizeof(log_id);
  // gettid() is a direct syscall wrapper in bionic (no allocation), used here instead
  // of any higher-level thread-id API.
  // 中文：gettid() 在 bionic 中是一个直接的系统调用封装（不涉及内存分配），这里
  // 使用它而不是任何更高层的线程 ID 接口。
  uint16_t tid = gettid();
  vec[1].iov_base = &tid;
  vec[1].iov_len = sizeof(tid);
  timespec ts;
  // CLOCK_REALTIME (wall-clock) is used here deliberately, unlike ktime.cpp's
  // CLOCK_MONOTONIC: logd wants an actual timestamp to display/sort log lines by,
  // not a duration, so wall-clock (even though it can jump on NTP sync) is correct.
  // 中文：这里特意使用 CLOCK_REALTIME（挂钟时间），而不是像 ktime.cpp 那样使用
  // CLOCK_MONOTONIC：logd 需要的是用于显示/排序日志行的实际时间戳，而不是一个
  // 时长，所以即使挂钟时间会因 NTP 同步而跳变，在这里使用它仍然是正确的。
  clock_gettime(CLOCK_REALTIME, &ts);
  log_time realtime_ts;
  realtime_ts.tv_sec = ts.tv_sec;
  realtime_ts.tv_nsec = ts.tv_nsec;
  vec[2].iov_base = &realtime_ts;
  vec[2].iov_len = sizeof(realtime_ts);

  vec[3].iov_base = &priority;
  vec[3].iov_len = 1;
  vec[4].iov_base = const_cast<char *>(tag);
  vec[4].iov_len = strlen(tag) + 1;
  vec[5].iov_base = const_cast<char *>(msg);
  vec[5].iov_len = strlen(msg) + 1;

  // writev() sends the whole logd wire-format entry in a single syscall (no libc
  // log-write helper involved, which is the point - see file-level note above).
  // 中文：writev() 用一次系统调用把整条 logd 线路格式日志条目发送出去（完全不涉及
  // libc 的日志写入辅助函数，这正是关键所在——参见上面文件级别的说明）。
  int result = TEMP_FAILURE_RETRY(writev(main_log_fd, vec, sizeof(vec) / sizeof(vec[0])));
  __close(main_log_fd);
  if (result == -1) {
    // Try stderr instead.
    result = write_stderr(priority, tag, msg);
  }
  return result;
}

/**
 * Format and emit a log line via async_safe_write_log(), on a stack buffer only (no
 * heap allocation anywhere in the call chain) - this is the primary entry point
 * intended for use from signal handlers/crash paths where regular __android_log_print
 * would be unsafe (it may call malloc() internally, see file-level note above).
 *
 * 中文：通过 async_safe_write_log() 格式化并输出一行日志，全程只使用栈上缓冲区
 * （调用链中没有任何堆内存分配）——这是供信号处理函数/崩溃处理路径使用的主要
 * 入口，在这些场景下普通的 __android_log_print 是不安全的（它内部可能调用
 * malloc()，参见上面文件级别的说明）。
 */
KWAI_EXPORT int async_safe_format_log_va_list(int priority, const char *tag, const char *format,
                                              va_list args) {
  ErrnoRestorer errno_restorer;
  char buffer[1024];
  BufferOutputStream os(buffer, sizeof(buffer));
  out_vformat(os, format, args);
  return async_safe_write_log(priority, tag, buffer);
}

/**
 * Varargs convenience wrapper around async_safe_format_log_va_list().
 *
 * 中文：async_safe_format_log_va_list() 的可变参数（varargs）便捷封装。
 */
KWAI_EXPORT int async_safe_format_log(int priority, const char *tag, const char *format, ...) {
  va_list args;
  va_start(args, format);
  int result = async_safe_format_log_va_list(priority, tag, format, args);
  va_end(args);
  return result;
}

/**
 * Format a fatal-error message onto a stack buffer and report it two ways: raw
 * writev() to stderr fd 2, and through async_safe_write_log() to logd. Kept
 * malloc-free throughout so it's safe to invoke from a crash/signal-handling path.
 *
 * 中文：把一条致命错误消息格式化到栈上缓冲区，并通过两种方式上报：直接对 fd 2
 * （stderr）执行 writev()，以及通过 async_safe_write_log() 发给 logd。全程不
 * 使用 malloc，因此可以安全地在崩溃/信号处理路径中调用。
 */
void async_safe_fatal_va_list(const char *prefix, const char *format, va_list args) {
  char msg[1024];
  BufferOutputStream os(msg, sizeof(msg));

  if (prefix) {
    os.Send(prefix, strlen(prefix));
    os.Send(": ", 2);
  }

  out_vformat(os, format, args);

  // Log to stderr for the benefit of "adb shell" users and gtests.
  struct iovec iov[2] = {
      {msg, strlen(msg)},
      {const_cast<char *>("\n"), 1},
  };
  // Raw writev() straight to fd 2, bypassing any buffered stdio - consistent with the
  // rest of this file's async-signal-safety approach (no allocation, no locks).
  // 中文：直接对 fd 2 执行原始 writev()，绕开任何带缓冲的 stdio——与本文件其余
  // 部分的异步信号安全做法保持一致（不分配内存、不加锁）。
  TEMP_FAILURE_RETRY(writev(2, iov, 2));

  // Log to the log for the benefit of regular app developers (whose stdout and stderr are closed).
  async_safe_write_log(ANDROID_LOG_FATAL, "libc", msg);
  kwai_set_abort_message(msg);
}

/**
 * Varargs convenience wrapper around async_safe_fatal_va_list() (does not itself
 * abort the process, despite the name mirroring async_safe_fatal()-style helpers).
 *
 * 中文：async_safe_fatal_va_list() 的可变参数（varargs）便捷封装（尽管函数名
 * 与 async_safe_fatal() 系列辅助函数相似，但它本身并不会使进程终止/abort）。
 */
void async_safe_fatal_no_abort(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  async_safe_fatal_va_list(nullptr, fmt, args);
  va_end(args);
}