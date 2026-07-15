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
 * Created by lbtrace on 2021.
 *
 */
#ifndef KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_CONCURRENT_HASH_MAP_H_
#define KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_CONCURRENT_HASH_MAP_H_

#include <map>
#include <mutex>
#include <vector>

/**
 * Hash map sharded into many independently-locked buckets (per-bucket mutex,
 * see Bucket below) instead of one map behind one global lock. This is used
 * as LeakMonitor's live_alloc_records_ table, which every hooked
 * malloc/free/realloc/... call across every thread in the process reads or
 * writes; sharding spreads that lock contention across kDefaultBucketNum
 * independent mutexes instead of serializing all threads' allocations
 * through a single lock.
 *
 * 中文：一个被分片成许多独立加锁桶（每个桶一把互斥锁，见下面的 Bucket）的
 * 哈希表，而不是用一把全局锁保护单一的 map。它被用作 LeakMonitor 的
 * live_alloc_records_ 表，进程内每个线程的每一次被 hook 的
 * malloc/free/realloc/... 调用都会读写这张表；分片可以把锁竞争分散到
 * kDefaultBucketNum 把独立的互斥锁上，而不是让所有线程的分配操作都串行地
 * 争抢同一把锁。
 */
template <typename K, typename V, typename Hash = std::hash<K>>
class ConcurrentHashMap {
 public:
  ConcurrentHashMap(unsigned bucketNumber = kDefaultBucketNum,
                    const Hash &hash = Hash())
      : table_(bucketNumber), hash_(hash) {}

  // Invokes `p` for every stored value across all buckets (each bucket
  // locked only while it is being iterated, not for the whole call).
  // 中文：对所有桶中存储的每一个值调用 `p`（每个桶只在被遍历期间加锁，
  // 而不是整个调用过程都持有锁）。
  template <typename Predicate>
  void Dump(Predicate &p) {
    for (auto &bucket : table_) {
      bucket.Dump(p);
    }
  }

  void Insert(const K &key, V &&value) {
    table_[Hashcode(key)].Insert(key, std::move(value));
  }

  void Put(const K &key, V &&value) {
    table_[Hashcode(key)].Put(key, std::move(value));
  }

  void Erase(const K &key) { table_[Hashcode(key)].Erase(key); }

  std::size_t Size() const {
    std::size_t size = 0;
    for (auto &bucket : table_) {
      size += bucket.Size();
    }
    return size;
  }

  std::size_t Count(const K &key) const {
    return table_[Hashcode(key)].Count(key);
  }

  void Clear() {
    for (auto &bucket : table_) {
      bucket.Clear();
    }
  }

 private:
  static const unsigned kDefaultBucketNum = 521;  // Prime Number is better

  // One shard: an independent std::map guarded by its own mutex, so
  // operations on keys that hash to different buckets never contend with
  // each other.
  // 中文：一个分片：一个由自己的互斥锁保护的独立 std::map，因此哈希到不同
  // 桶的键上的操作永远不会互相竞争。
  class Bucket {
   public:
    void Insert(const K &key, V &&value) {
      std::lock_guard<std::mutex> lock(mutex_);
      item_.emplace(key, std::move(value));
    }

    void Put(const K &key, V &&value) {
      std::lock_guard<std::mutex> lock(mutex_);
      item_.erase(key);
      item_.emplace(key, std::move(value));
    }

    void Erase(const K &key) {
      std::lock_guard<std::mutex> lock(mutex_);
      item_.erase(key);
    }

    template <typename Predicate>
    void Dump(Predicate &p) {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto it = item_.begin(); it != item_.end(); it++) {
        p(it->second);
      }
    }

    std::size_t Size() const {
      std::lock_guard<std::mutex> lock(mutex_);
      return item_.size();
    }

    std::size_t Count(const K &key) const {
      std::lock_guard<std::mutex> lock(mutex_);
      return item_.count(key);
    }

    void Clear() {
      std::lock_guard<std::mutex> lock(mutex_);
      item_.clear();
    }

   private:
    using Item = std::map<K, V>;
    Item item_;
    mutable std::mutex mutex_;
  };

  // Picks which bucket/shard a key belongs to; using a prime bucket count
  // (kDefaultBucketNum) helps spread hash values more evenly across buckets.
  // 中文：选出某个键属于哪个桶/分片；使用一个质数作为桶的数量
  // （kDefaultBucketNum），有助于让哈希值更均匀地分散到各个桶中。
  inline std::size_t Hashcode(const K &key) {
    return hash_(key) % table_.size();
  }

  std::vector<Bucket> table_;
  Hash hash_;
};
#endif  // KOOM_NATIVE_OOM_SRC_MAIN_JNI_INCLUDE_UTILS_CONCURRENT_HASH_MAP_H_