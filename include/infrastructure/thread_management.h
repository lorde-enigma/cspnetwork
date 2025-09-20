#pragma once

#include <thread>
#include <future>
#include <queue>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <memory>
#include <chrono>

namespace CipherProxy::Infrastructure {

class ThreadPool {
public:
    explicit ThreadPool(size_t thread_count = std::thread::hardware_concurrency());
    ~ThreadPool();
    
    template<typename F, typename... Args>
    auto submit(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
    
    void start();
    void stop();
    void wait_for_completion();
    
    size_t get_thread_count() const;
    size_t get_pending_tasks() const;
    bool is_running() const;
    
    void set_cpu_affinity(bool enable);
    void set_thread_priority(int priority);

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    mutable std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_flag_;
    std::atomic<bool> started_;
    std::atomic<size_t> active_threads_;
    
    bool cpu_affinity_enabled_;
    int thread_priority_;
    
    void worker_thread(size_t thread_id);
    void configure_thread(size_t thread_id);
};

class WorkerThread {
public:
    explicit WorkerThread(const std::string& name = "");
    ~WorkerThread();
    
    template<typename F>
    void post_task(F&& task);
    
    void start();
    void stop();
    void join();
    
    bool is_running() const;
    size_t get_pending_tasks() const;
    const std::string& get_name() const;

private:
    std::string name_;
    std::thread worker_;
    std::queue<std::function<void()>> tasks_;
    mutable std::mutex task_mutex_;
    std::condition_variable task_condition_;
    std::atomic<bool> stop_flag_;
    std::atomic<bool> running_;
    
    void worker_loop();
};

template<typename T>
class LockFreeQueue {
public:
    LockFreeQueue();
    ~LockFreeQueue();
    
    void push(const T& item);
    void push(T&& item);
    bool pop(T& item);
    bool empty() const;
    size_t size() const;

private:
    struct Node {
        std::atomic<T*> data;
        std::atomic<Node*> next;
        Node() : data(nullptr), next(nullptr) {}
    };
    
    std::atomic<Node*> head_;
    std::atomic<Node*> tail_;
    std::atomic<size_t> size_;
};

class CPUAffinityManager {
public:
    static CPUAffinityManager& instance();
    
    void set_thread_affinity(std::thread::id thread_id, const std::vector<int>& cpu_cores);
    void distribute_threads_across_cores(const std::vector<std::thread::id>& threads);
    void enable_numa_awareness(bool enable);
    
    std::vector<int> get_available_cores() const;
    std::vector<int> get_numa_nodes() const;
    int get_core_for_thread(std::thread::id thread_id) const;

private:
    CPUAffinityManager() = default;
    mutable std::mutex affinity_mutex_;
    std::unordered_map<std::thread::id, std::vector<int>> thread_affinities_;
    bool numa_awareness_enabled_;
};

class ThreadSafeCounter {
public:
    ThreadSafeCounter() : value_(0) {}
    
    uint64_t increment() { return value_.fetch_add(1) + 1; }
    uint64_t decrement() { return value_.fetch_sub(1) - 1; }
    uint64_t get() const { return value_.load(); }
    void set(uint64_t value) { value_.store(value); }
    void reset() { value_.store(0); }
    
    uint64_t add(uint64_t delta) { return value_.fetch_add(delta) + delta; }
    uint64_t subtract(uint64_t delta) { return value_.fetch_sub(delta) - delta; }

private:
    std::atomic<uint64_t> value_;
};

template<typename T>
class ThreadSafeRingBuffer {
public:
    explicit ThreadSafeRingBuffer(size_t capacity);
    ~ThreadSafeRingBuffer();
    
    bool push(const T& item);
    bool push(T&& item);
    bool pop(T& item);
    
    bool empty() const;
    bool full() const;
    size_t size() const;
    size_t capacity() const;
    
    void clear();

private:
    std::vector<T> buffer_;
    std::atomic<size_t> head_;
    std::atomic<size_t> tail_;
    size_t capacity_;
    size_t mask_;
    
    static bool is_power_of_two(size_t n) {
        return n > 0 && (n & (n - 1)) == 0;
    }
    
    static size_t next_power_of_two(size_t n) {
        if (is_power_of_two(n)) return n;
        n--;
        n |= n >> 1;
        n |= n >> 2;
        n |= n >> 4;
        n |= n >> 8;
        n |= n >> 16;
        n |= n >> 32;
        return n + 1;
    }
};

class PerformanceMonitor {
public:
    static PerformanceMonitor& instance();
    
    void start_monitoring();
    void stop_monitoring();
    
    struct ThreadMetrics {
        std::thread::id thread_id;
        std::string thread_name;
        double cpu_usage_percent;
        uint64_t tasks_processed;
        std::chrono::milliseconds avg_task_time;
        std::chrono::steady_clock::time_point last_activity;
    };
    
    struct SystemMetrics {
        double overall_cpu_usage;
        size_t memory_usage_mb;
        size_t active_threads;
        size_t pending_tasks;
        double tasks_per_second;
    };
    
    ThreadMetrics get_thread_metrics(std::thread::id thread_id) const;
    SystemMetrics get_system_metrics() const;
    std::vector<ThreadMetrics> get_all_thread_metrics() const;
    
    void register_thread(std::thread::id thread_id, const std::string& name);
    void unregister_thread(std::thread::id thread_id);
    void record_task_completion(std::thread::id thread_id, std::chrono::milliseconds duration);

private:
    PerformanceMonitor() = default;
    
    mutable std::mutex metrics_mutex_;
    std::unordered_map<std::thread::id, ThreadMetrics> thread_metrics_;
    std::atomic<bool> monitoring_active_;
    std::thread monitor_thread_;
    
    void monitor_loop();
    void update_system_metrics();
};

class ThreadManager {
public:
    static ThreadManager& instance();
    
    void initialize(size_t io_threads = 4, size_t worker_threads = 0, size_t crypto_threads = 2);
    void shutdown();
    
    ThreadPool& get_io_pool();
    ThreadPool& get_worker_pool();
    ThreadPool& get_crypto_pool();
    
    template<typename F, typename... Args>
    auto submit_io_task(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
    
    template<typename F, typename... Args>
    auto submit_worker_task(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
    
    template<typename F, typename... Args>
    auto submit_crypto_task(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
    
    void optimize_for_system();
    bool is_initialized() const;

private:
    ThreadManager() = default;
    
    std::unique_ptr<ThreadPool> io_pool_;
    std::unique_ptr<ThreadPool> worker_pool_;
    std::unique_ptr<ThreadPool> crypto_pool_;
    std::atomic<bool> initialized_;
    
    void detect_optimal_thread_counts();
};

}

#include "thread_management.inl"
