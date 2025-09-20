#pragma once

#include <functional>
#include <new>

namespace CipherProxy::Infrastructure {

template<typename T>
ObjectPool<T>::ObjectPool(size_t initial_size, size_t max_size)
    : total_objects_(0), max_size_(max_size) {
    grow_pool(initial_size);
}

template<typename T>
ObjectPool<T>::~ObjectPool() {
    clear();
}

template<typename T>
std::unique_ptr<T> ObjectPool<T>::acquire() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    if (!available_objects_.empty()) {
        auto obj = std::move(available_objects_.top());
        available_objects_.pop();
        return obj;
    }
    
    if (total_objects_.load() < max_size_) {
        grow_pool(1);
        if (!available_objects_.empty()) {
            auto obj = std::move(available_objects_.top());
            available_objects_.pop();
            return obj;
        }
    }
    
    return std::make_unique<T>();
}

template<typename T>
void ObjectPool<T>::release(std::unique_ptr<T> obj) {
    if (!obj) return;
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    if (available_objects_.size() < max_size_) {
        if constexpr (std::is_base_of_v<ConnectionContext, T>) {
            static_cast<ConnectionContext*>(obj.get())->reset();
        }
        available_objects_.push(std::move(obj));
    }
}

template<typename T>
size_t ObjectPool<T>::available_count() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return available_objects_.size();
}

template<typename T>
size_t ObjectPool<T>::total_count() const {
    return total_objects_.load();
}

template<typename T>
void ObjectPool<T>::resize(size_t new_size) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    if (new_size > max_size_) {
        max_size_ = new_size;
    }
    
    if (new_size > available_objects_.size()) {
        grow_pool(new_size - available_objects_.size());
    } else {
        while (available_objects_.size() > new_size) {
            available_objects_.pop();
            total_objects_--;
        }
    }
}

template<typename T>
void ObjectPool<T>::clear() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    while (!available_objects_.empty()) {
        available_objects_.pop();
    }
    total_objects_ = 0;
}

template<typename T>
void ObjectPool<T>::grow_pool(size_t count) {
    for (size_t i = 0; i < count && total_objects_.load() < max_size_; ++i) {
        available_objects_.push(std::make_unique<T>());
        total_objects_++;
    }
}

template<typename T>
ObjectPool<T>& MemoryPoolManager::get_object_pool() {
    static ObjectPool<T> pool;
    return pool;
}

template<typename T>
typename PooledAllocator<T>::pointer PooledAllocator<T>::allocate(size_type n) {
    if (n == 1 && !free_blocks_.empty()) {
        auto ptr = static_cast<pointer>(free_blocks_.top());
        free_blocks_.pop();
        return ptr;
    }
    
    return static_cast<pointer>(::operator new(n * sizeof(T)));
}

template<typename T>
void PooledAllocator<T>::deallocate(pointer p, size_type n) {
    if (n == 1 && free_blocks_.size() < BLOCK_SIZE / sizeof(T)) {
        free_blocks_.push(p);
        return;
    }
    
    ::operator delete(p);
}

template<typename T>
template<typename U, typename... Args>
void PooledAllocator<T>::construct(U* p, Args&&... args) {
    new(p) U(std::forward<Args>(args)...);
}

template<typename T>
template<typename U>
void PooledAllocator<T>::destroy(U* p) {
    p->~U();
}

template<typename T>
thread_local std::stack<void*> PooledAllocator<T>::free_blocks_;

}
