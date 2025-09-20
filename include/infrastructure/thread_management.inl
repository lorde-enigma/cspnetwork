#pragma once

#include <type_traits>
#include <unordered_map>

namespace CipherProxy::Infrastructure {

template<typename F, typename... Args>
auto ThreadPool::submit(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    using return_type = typename std::result_of<F(Args...)>::type;
    
    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );
    
    std::future<return_type> result = task->get_future();
    
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (stop_flag_.load()) {
            throw std::runtime_error("cannot submit task to stopped thread pool");
        }
        tasks_.emplace([task]() { (*task)(); });
    }
    
    condition_.notify_one();
    return result;
}

template<typename F>
void WorkerThread::post_task(F&& task) {
    {
        std::lock_guard<std::mutex> lock(task_mutex_);
        tasks_.emplace(std::forward<F>(task));
    }
    task_condition_.notify_one();
}

template<typename T>
LockFreeQueue<T>::LockFreeQueue() : size_(0) {
    Node* dummy = new Node;
    head_.store(dummy);
    tail_.store(dummy);
}

template<typename T>
LockFreeQueue<T>::~LockFreeQueue() {
    while (Node* const old_head = head_.load()) {
        head_.store(old_head->next);
        delete old_head;
    }
}

template<typename T>
void LockFreeQueue<T>::push(const T& item) {
    Node* new_node = new Node;
    T* data = new T(item);
    new_node->data.store(data);
    
    Node* prev_tail = tail_.exchange(new_node);
    prev_tail->next.store(new_node);
    size_.fetch_add(1);
}

template<typename T>
void LockFreeQueue<T>::push(T&& item) {
    Node* new_node = new Node;
    T* data = new T(std::move(item));
    new_node->data.store(data);
    
    Node* prev_tail = tail_.exchange(new_node);
    prev_tail->next.store(new_node);
    size_.fetch_add(1);
}

template<typename T>
bool LockFreeQueue<T>::pop(T& item) {
    Node* head = head_.load();
    Node* next = head->next.load();
    
    if (next == nullptr) {
        return false;
    }
    
    T* data = next->data.load();
    if (data == nullptr) {
        return false;
    }
    
    item = *data;
    delete data;
    head_.store(next);
    delete head;
    size_.fetch_sub(1);
    
    return true;
}

template<typename T>
bool LockFreeQueue<T>::empty() const {
    return size_.load() == 0;
}

template<typename T>
size_t LockFreeQueue<T>::size() const {
    return size_.load();
}

template<typename T>
ThreadSafeRingBuffer<T>::ThreadSafeRingBuffer(size_t capacity)
    : capacity_(next_power_of_two(capacity)), mask_(capacity_ - 1), head_(0), tail_(0) {
    buffer_.resize(capacity_);
}

template<typename T>
ThreadSafeRingBuffer<T>::~ThreadSafeRingBuffer() = default;

template<typename T>
bool ThreadSafeRingBuffer<T>::push(const T& item) {
    size_t current_tail = tail_.load(std::memory_order_relaxed);
    size_t next_tail = (current_tail + 1) & mask_;
    
    if (next_tail == head_.load(std::memory_order_acquire)) {
        return false; // Buffer is full
    }
    
    buffer_[current_tail] = item;
    tail_.store(next_tail, std::memory_order_release);
    return true;
}

template<typename T>
bool ThreadSafeRingBuffer<T>::push(T&& item) {
    size_t current_tail = tail_.load(std::memory_order_relaxed);
    size_t next_tail = (current_tail + 1) & mask_;
    
    if (next_tail == head_.load(std::memory_order_acquire)) {
        return false; // Buffer is full
    }
    
    buffer_[current_tail] = std::move(item);
    tail_.store(next_tail, std::memory_order_release);
    return true;
}

template<typename T>
bool ThreadSafeRingBuffer<T>::pop(T& item) {
    size_t current_head = head_.load(std::memory_order_relaxed);
    
    if (current_head == tail_.load(std::memory_order_acquire)) {
        return false; // Buffer is empty
    }
    
    item = std::move(buffer_[current_head]);
    head_.store((current_head + 1) & mask_, std::memory_order_release);
    return true;
}

template<typename T>
bool ThreadSafeRingBuffer<T>::empty() const {
    return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
}

template<typename T>
bool ThreadSafeRingBuffer<T>::full() const {
    size_t next_tail = (tail_.load(std::memory_order_acquire) + 1) & mask_;
    return next_tail == head_.load(std::memory_order_acquire);
}

template<typename T>
size_t ThreadSafeRingBuffer<T>::size() const {
    size_t head = head_.load(std::memory_order_acquire);
    size_t tail = tail_.load(std::memory_order_acquire);
    return (tail - head) & mask_;
}

template<typename T>
size_t ThreadSafeRingBuffer<T>::capacity() const {
    return capacity_;
}

template<typename T>
void ThreadSafeRingBuffer<T>::clear() {
    head_.store(0, std::memory_order_release);
    tail_.store(0, std::memory_order_release);
}

template<typename F, typename... Args>
auto ThreadManager::submit_io_task(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    if (!io_pool_) {
        throw std::runtime_error("thread manager not initialized");
    }
    return io_pool_->submit(std::forward<F>(f), std::forward<Args>(args)...);
}

template<typename F, typename... Args>
auto ThreadManager::submit_worker_task(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    if (!worker_pool_) {
        throw std::runtime_error("thread manager not initialized");
    }
    return worker_pool_->submit(std::forward<F>(f), std::forward<Args>(args)...);
}

template<typename F, typename... Args>
auto ThreadManager::submit_crypto_task(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    if (!crypto_pool_) {
        throw std::runtime_error("thread manager not initialized");
    }
    return crypto_pool_->submit(std::forward<F>(f), std::forward<Args>(args)...);
}

}
