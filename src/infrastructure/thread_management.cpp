#include "infrastructure/thread_management.h"
#include <algorithm>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace CipherProxy::Infrastructure {

ThreadPool::ThreadPool(size_t thread_count)
    : stop_flag_(false), started_(false), active_threads_(0),
      cpu_affinity_enabled_(false), thread_priority_(0) {
    workers_.reserve(thread_count);
}

ThreadPool::~ThreadPool() {
    stop();
}

void ThreadPool::start() {
    if (started_.exchange(true)) {
        return;
    }
    
    stop_flag_.store(false);
    
    for (size_t i = 0; i < workers_.capacity(); ++i) {
        workers_.emplace_back(&ThreadPool::worker_thread, this, i);
    }
}

void ThreadPool::stop() {
    if (!started_.load()) {
        return;
    }
    
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_flag_.store(true);
    }
    
    condition_.notify_all();
    
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    workers_.clear();
    started_.store(false);
}

void ThreadPool::wait_for_completion() {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    condition_.wait(lock, [this] {
        return tasks_.empty() && active_threads_.load() == 0;
    });
}

size_t ThreadPool::get_thread_count() const {
    return workers_.size();
}

size_t ThreadPool::get_pending_tasks() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return tasks_.size();
}

bool ThreadPool::is_running() const {
    return started_.load() && !stop_flag_.load();
}

void ThreadPool::set_cpu_affinity(bool enable) {
    cpu_affinity_enabled_ = enable;
}

void ThreadPool::set_thread_priority(int priority) {
    thread_priority_ = priority;
}

void ThreadPool::worker_thread(size_t thread_id) {
    configure_thread(thread_id);
    
    PerformanceMonitor::instance().register_thread(std::this_thread::get_id(),
        "ThreadPool-" + std::to_string(thread_id));
    
    while (true) {
        std::function<void()> task;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            condition_.wait(lock, [this] { return stop_flag_.load() || !tasks_.empty(); });
            
            if (stop_flag_.load() && tasks_.empty()) {
                break;
            }
            
            if (!tasks_.empty()) {
                task = std::move(tasks_.front());
                tasks_.pop();
            }
        }
        
        if (task) {
            active_threads_.fetch_add(1);
            auto start_time = std::chrono::steady_clock::now();
            
            try {
                task();
            } catch (const std::exception& e) {
                // Log error
            }
            
            auto end_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            
            PerformanceMonitor::instance().record_task_completion(std::this_thread::get_id(), duration);
            active_threads_.fetch_sub(1);
        }
    }
    
    PerformanceMonitor::instance().unregister_thread(std::this_thread::get_id());
}

void ThreadPool::configure_thread(size_t thread_id) {
    if (cpu_affinity_enabled_) {
        auto& affinity_manager = CPUAffinityManager::instance();
        auto available_cores = affinity_manager.get_available_cores();
        
        if (!available_cores.empty()) {
            std::vector<int> core_assignment = {available_cores[thread_id % available_cores.size()]};
            affinity_manager.set_thread_affinity(std::this_thread::get_id(), core_assignment);
        }
    }
    
    if (thread_priority_ != 0) {
        struct sched_param param;
        param.sched_priority = thread_priority_;
        pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
    }
}

WorkerThread::WorkerThread(const std::string& name)
    : name_(name.empty() ? "WorkerThread" : name), stop_flag_(false), running_(false) {}

WorkerThread::~WorkerThread() {
    stop();
    join();
}

void WorkerThread::start() {
    if (running_.exchange(true)) {
        return;
    }
    
    stop_flag_.store(false);
    worker_ = std::thread(&WorkerThread::worker_loop, this);
}

void WorkerThread::stop() {
    if (!running_.load()) {
        return;
    }
    
    stop_flag_.store(true);
    task_condition_.notify_all();
}

void WorkerThread::join() {
    if (worker_.joinable()) {
        worker_.join();
    }
    running_.store(false);
}

bool WorkerThread::is_running() const {
    return running_.load();
}

size_t WorkerThread::get_pending_tasks() const {
    std::lock_guard<std::mutex> lock(task_mutex_);
    return tasks_.size();
}

const std::string& WorkerThread::get_name() const {
    return name_;
}

void WorkerThread::worker_loop() {
    PerformanceMonitor::instance().register_thread(std::this_thread::get_id(), name_);
    
    while (!stop_flag_.load()) {
        std::function<void()> task;
        
        {
            std::unique_lock<std::mutex> lock(task_mutex_);
            task_condition_.wait(lock, [this] { return stop_flag_.load() || !tasks_.empty(); });
            
            if (!tasks_.empty()) {
                task = std::move(tasks_.front());
                tasks_.pop();
            }
        }
        
        if (task) {
            auto start_time = std::chrono::steady_clock::now();
            
            try {
                task();
            } catch (const std::exception& e) {
                // Log error
            }
            
            auto end_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            
            PerformanceMonitor::instance().record_task_completion(std::this_thread::get_id(), duration);
        }
    }
    
    PerformanceMonitor::instance().unregister_thread(std::this_thread::get_id());
}

CPUAffinityManager& CPUAffinityManager::instance() {
    static CPUAffinityManager instance;
    return instance;
}

void CPUAffinityManager::set_thread_affinity(std::thread::id thread_id, const std::vector<int>& cpu_cores) {
    std::lock_guard<std::mutex> lock(affinity_mutex_);
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    
    for (int core : cpu_cores) {
        CPU_SET(core, &cpuset);
    }
    
    auto native_handle = pthread_self(); // This should be called from the target thread
    if (pthread_setaffinity_np(native_handle, sizeof(cpu_set_t), &cpuset) == 0) {
        thread_affinities_[thread_id] = cpu_cores;
    }
}

void CPUAffinityManager::distribute_threads_across_cores(const std::vector<std::thread::id>& threads) {
    auto available_cores = get_available_cores();
    if (available_cores.empty()) return;
    
    for (size_t i = 0; i < threads.size(); ++i) {
        int core = available_cores[i % available_cores.size()];
        set_thread_affinity(threads[i], {core});
    }
}

void CPUAffinityManager::enable_numa_awareness(bool enable) {
    numa_awareness_enabled_ = enable;
}

std::vector<int> CPUAffinityManager::get_available_cores() const {
    std::vector<int> cores;
    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    
    for (int i = 0; i < num_cores; ++i) {
        cores.push_back(i);
    }
    
    return cores;
}

std::vector<int> CPUAffinityManager::get_numa_nodes() const {
    // Simplified implementation - would need libnuma for full functionality
    return {0};
}

int CPUAffinityManager::get_core_for_thread(std::thread::id thread_id) const {
    std::lock_guard<std::mutex> lock(affinity_mutex_);
    
    auto it = thread_affinities_.find(thread_id);
    if (it != thread_affinities_.end() && !it->second.empty()) {
        return it->second[0];
    }
    
    return -1;
}

PerformanceMonitor& PerformanceMonitor::instance() {
    static PerformanceMonitor instance;
    return instance;
}

void PerformanceMonitor::start_monitoring() {
    if (monitoring_active_.exchange(true)) {
        return;
    }
    
    monitor_thread_ = std::thread(&PerformanceMonitor::monitor_loop, this);
}

void PerformanceMonitor::stop_monitoring() {
    if (!monitoring_active_.exchange(false)) {
        return;
    }
    
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

PerformanceMonitor::ThreadMetrics PerformanceMonitor::get_thread_metrics(std::thread::id thread_id) const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto it = thread_metrics_.find(thread_id);
    if (it != thread_metrics_.end()) {
        return it->second;
    }
    
    return ThreadMetrics{};
}

PerformanceMonitor::SystemMetrics PerformanceMonitor::get_system_metrics() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    SystemMetrics metrics{};
    metrics.active_threads = thread_metrics_.size();
    metrics.pending_tasks = 0;
    
    double total_cpu = 0.0;
    uint64_t total_tasks = 0;
    
    for (const auto& [thread_id, thread_metrics] : thread_metrics_) {
        total_cpu += thread_metrics.cpu_usage_percent;
        total_tasks += thread_metrics.tasks_processed;
    }
    
    metrics.overall_cpu_usage = total_cpu / std::max(1.0, static_cast<double>(thread_metrics_.size()));
    
    // Simple memory usage estimation
    metrics.memory_usage_mb = thread_metrics_.size() * 8; // 8MB per thread estimate
    
    return metrics;
}

std::vector<PerformanceMonitor::ThreadMetrics> PerformanceMonitor::get_all_thread_metrics() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::vector<ThreadMetrics> metrics;
    metrics.reserve(thread_metrics_.size());
    
    for (const auto& [thread_id, thread_metrics] : thread_metrics_) {
        metrics.push_back(thread_metrics);
    }
    
    return metrics;
}

void PerformanceMonitor::register_thread(std::thread::id thread_id, const std::string& name) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    ThreadMetrics& metrics = thread_metrics_[thread_id];
    metrics.thread_id = thread_id;
    metrics.thread_name = name;
    metrics.cpu_usage_percent = 0.0;
    metrics.tasks_processed = 0;
    metrics.avg_task_time = std::chrono::milliseconds(0);
    metrics.last_activity = std::chrono::steady_clock::now();
}

void PerformanceMonitor::unregister_thread(std::thread::id thread_id) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    thread_metrics_.erase(thread_id);
}

void PerformanceMonitor::record_task_completion(std::thread::id thread_id, std::chrono::milliseconds duration) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto it = thread_metrics_.find(thread_id);
    if (it != thread_metrics_.end()) {
        auto& metrics = it->second;
        metrics.tasks_processed++;
        metrics.last_activity = std::chrono::steady_clock::now();
        
        // Exponential moving average for task time
        double alpha = 0.1;
        double new_avg = (1.0 - alpha) * metrics.avg_task_time.count() + alpha * duration.count();
        metrics.avg_task_time = std::chrono::milliseconds(static_cast<int64_t>(new_avg));
    }
}

void PerformanceMonitor::monitor_loop() {
    while (monitoring_active_.load()) {
        update_system_metrics();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void PerformanceMonitor::update_system_metrics() {
    // Update CPU usage and other system metrics
    // This would typically read from /proc/stat, /proc/meminfo, etc.
}

ThreadManager& ThreadManager::instance() {
    static ThreadManager instance;
    return instance;
}

void ThreadManager::initialize(size_t io_threads, size_t worker_threads, size_t crypto_threads) {
    if (initialized_.exchange(true)) {
        return;
    }
    
    if (worker_threads == 0) {
        worker_threads = std::max(1u, static_cast<unsigned int>(std::thread::hardware_concurrency() - io_threads - crypto_threads));
    }
    
    io_pool_ = std::make_unique<ThreadPool>(io_threads);
    worker_pool_ = std::make_unique<ThreadPool>(worker_threads);
    crypto_pool_ = std::make_unique<ThreadPool>(crypto_threads);
    
    io_pool_->start();
    worker_pool_->start();
    crypto_pool_->start();
    
    optimize_for_system();
}

void ThreadManager::shutdown() {
    if (!initialized_.exchange(false)) {
        return;
    }
    
    if (io_pool_) {
        io_pool_->stop();
        io_pool_.reset();
    }
    
    if (worker_pool_) {
        worker_pool_->stop();
        worker_pool_.reset();
    }
    
    if (crypto_pool_) {
        crypto_pool_->stop();
        crypto_pool_.reset();
    }
}

ThreadPool& ThreadManager::get_io_pool() {
    if (!io_pool_) {
        throw std::runtime_error("thread manager not initialized");
    }
    return *io_pool_;
}

ThreadPool& ThreadManager::get_worker_pool() {
    if (!worker_pool_) {
        throw std::runtime_error("thread manager not initialized");
    }
    return *worker_pool_;
}

ThreadPool& ThreadManager::get_crypto_pool() {
    if (!crypto_pool_) {
        throw std::runtime_error("thread manager not initialized");
    }
    return *crypto_pool_;
}

void ThreadManager::optimize_for_system() {
    auto& affinity_manager = CPUAffinityManager::instance();
    auto available_cores = affinity_manager.get_available_cores();
    
    if (available_cores.size() >= 4) {
        io_pool_->set_cpu_affinity(true);
        worker_pool_->set_cpu_affinity(true);
        crypto_pool_->set_cpu_affinity(true);
    }
    
    // Set higher priority for I/O threads
    io_pool_->set_thread_priority(1);
}

bool ThreadManager::is_initialized() const {
    return initialized_.load();
}

}
