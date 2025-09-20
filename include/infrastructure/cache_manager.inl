#pragma once

namespace CipherProxy::Infrastructure {

template<typename Key, typename Value>
LRUCache<Key, Value>::LRUCache(size_t max_size, Duration ttl)
    : max_size_(max_size), ttl_(ttl) {
    cache_.reserve(max_size);
}

template <typename Key, typename Value>
void LRUCache<Key, Value>::put(const Key& key, Value value) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        it->second.first.value = std::move(value);
        it->second.first.last_accessed = std::chrono::steady_clock::now();
        it->second.first.access_count.fetch_add(1);
        touch(key, it);
        return;
    }
    
    if (cache_.size() >= max_size_) {
        evict_lru();
    }
    
    access_order_.emplace_front(key);
    auto list_it = access_order_.begin();
    cache_.emplace(key, std::make_pair(CacheEntry{std::move(value)}, list_it));
}

template<typename Key, typename Value>
std::optional<Value> LRUCache<Key, Value>::get(const Key& key) {
    std::shared_lock<std::shared_mutex> read_lock(mutex_);
    
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        misses_.fetch_add(1);
        return std::nullopt;
    }
    
    if (is_expired(it->second.first)) {
        read_lock.unlock();
        std::unique_lock<std::shared_mutex> write_lock(mutex_);
        
        it = cache_.find(key);
        if (it != cache_.end() && is_expired(it->second.first)) {
            access_order_.erase(it->second.second);
            cache_.erase(it);
            expired_cleanups_.fetch_add(1);
        }
        misses_.fetch_add(1);
        return std::nullopt;
    }
    
    hits_.fetch_add(1);
    it->second.first.last_accessed = std::chrono::steady_clock::now();
    it->second.first.access_count.fetch_add(1);
    
    read_lock.unlock();
    std::unique_lock<std::shared_mutex> write_lock(mutex_);
    
    it = cache_.find(key);
    if (it != cache_.end()) {
        access_order_.erase(it->second.second);
        access_order_.push_front(key);
        it->second.second = access_order_.begin();
        
        return it->second.first.value;
    }
    
    return std::nullopt;
}

template<typename Key, typename Value>
bool LRUCache<Key, Value>::contains(const Key& key) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    auto it = cache_.find(key);
    if (it == cache_.end()) {
        return false;
    }
    
    return !is_expired(it->second.first);
}

template<typename Key, typename Value>
void LRUCache<Key, Value>::remove(const Key& key) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        access_order_.erase(it->second.second);
        cache_.erase(it);
    }
}

template<typename Key, typename Value>
void LRUCache<Key, Value>::clear() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    cache_.clear();
    access_order_.clear();
}

template<typename Key, typename Value>
size_t LRUCache<Key, Value>::size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return cache_.size();
}

template<typename Key, typename Value>
size_t LRUCache<Key, Value>::max_size() const {
    return max_size_;
}

template<typename Key, typename Value>
bool LRUCache<Key, Value>::empty() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return cache_.empty();
}

template<typename Key, typename Value>
void LRUCache<Key, Value>::set_ttl(Duration ttl) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    ttl_ = ttl;
}

template<typename Key, typename Value>
void LRUCache<Key, Value>::cleanup_expired() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = cache_.begin();
    while (it != cache_.end()) {
        if (is_expired(it->second.first)) {
            access_order_.erase(it->second.second);
            it = cache_.erase(it);
            expired_cleanups_.fetch_add(1);
        } else {
            ++it;
        }
    }
}

template<typename Key, typename Value>
typename LRUCache<Key, Value>::Stats LRUCache<Key, Value>::get_stats() const {
    return Stats{
        hits_.load(),
        misses_.load(),
        evictions_.load(),
        expired_cleanups_.load()
    };
}

template<typename Key, typename Value>
void LRUCache<Key, Value>::reset_stats() {
    hits_.store(0);
    misses_.store(0);
    evictions_.store(0);
    expired_cleanups_.store(0);
}

template<typename Key, typename Value>
void LRUCache<Key, Value>::evict_lru() {
    if (!access_order_.empty()) {
        const Key& lru_key = access_order_.back();
        auto it = cache_.find(lru_key);
        if (it != cache_.end()) {
            cache_.erase(it);
        }
        access_order_.pop_back();
        evictions_.fetch_add(1);
    }
}

template<typename Key, typename Value>
bool LRUCache<Key, Value>::is_expired(const CacheEntry& entry) const {
    if (ttl_ == Duration::max()) {
        return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    return (now - entry.created_at) > ttl_;
}

template<typename Key, typename Value>
void LRUCache<Key, Value>::touch(const Key& key, typename decltype(cache_)::iterator it) {
    access_order_.erase(it->second.second);
    access_order_.push_front(key);
    it->second.second = access_order_.begin();
}

template<typename Key, typename Value>
ThreadSafeCache<Key, Value>::ThreadSafeCache(size_t max_size, std::chrono::milliseconds ttl)
    : cache_(max_size, ttl) {}

template<typename Key, typename Value>
Value ThreadSafeCache<Key, Value>::get_or_compute(const Key& key, CacheFunction compute_func) {
    auto cached_value = cache_.get(key);
    if (cached_value.has_value()) {
        return *cached_value;
    }
    
    std::unique_lock<std::shared_mutex> lock(compute_mutex_);
    
    cached_value = cache_.get(key);
    if (cached_value.has_value()) {
        return *cached_value;
    }
    
    Value computed_value = compute_func(key);
    cache_.put(key, computed_value);
    
    return computed_value;
}

template<typename Key, typename Value>
void ThreadSafeCache<Key, Value>::put(const Key& key, Value value) {
    cache_.put(key, std::move(value));
}

template<typename Key, typename Value>
std::optional<Value> ThreadSafeCache<Key, Value>::get(const Key& key) {
    return cache_.get(key);
}

template<typename Key, typename Value>
void ThreadSafeCache<Key, Value>::remove(const Key& key) {
    cache_.remove(key);
}

template<typename Key, typename Value>
void ThreadSafeCache<Key, Value>::clear() {
    cache_.clear();
}

template<typename Key, typename Value>
size_t ThreadSafeCache<Key, Value>::size() const {
    return cache_.size();
}

template<typename Key, typename Value>
bool ThreadSafeCache<Key, Value>::empty() const {
    return cache_.empty();
}

template<typename Key, typename Value>
double ThreadSafeCache<Key, Value>::hit_ratio() const {
    auto stats = cache_.get_stats();
    return stats.hit_ratio();
}

}
