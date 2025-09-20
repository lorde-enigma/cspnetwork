#pragma once

#include <memory>
#include <vector>
#include <stack>
#include <mutex>
#include <atomic>
#include <cstddef>
#include <type_traits>
#include <functional>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <queue>
#include <condition_variable>

namespace CipherProxy::Infrastructure {

template<typename T>
class ObjectPool {
public:
    explicit ObjectPool(size_t initial_size = 64, size_t max_size = 1024);
    ~ObjectPool();

    std::unique_ptr<T> acquire();
    void release(std::unique_ptr<T> obj);
    
    size_t available_count() const;
    size_t total_count() const;
    
    void resize(size_t new_size);
    void clear();

private:
    std::stack<std::unique_ptr<T>> available_objects_;
    mutable std::mutex pool_mutex_;
    std::atomic<size_t> total_objects_;
    size_t max_size_;
    
    void grow_pool(size_t count);
};

class PacketBuffer {
public:
    static constexpr size_t DEFAULT_BUFFER_SIZE = 65536;
    static constexpr size_t MAX_PACKET_SIZE = 65507;
    
    explicit PacketBuffer(size_t size = DEFAULT_BUFFER_SIZE);
    ~PacketBuffer();
    
    uint8_t* data() { return buffer_; }
    const uint8_t* data() const { return buffer_; }
    size_t size() const { return size_; }
    size_t capacity() const { return capacity_; }
    
    void resize(size_t new_size);
    void clear();
    void reset();
    
    bool append(const uint8_t* data, size_t length);
    bool prepend(const uint8_t* data, size_t length);
    
    void consume(size_t bytes);
    uint8_t* reserve(size_t bytes);

private:
    uint8_t* buffer_;
    size_t size_;
    size_t capacity_;
    size_t offset_;
    
    bool ensure_capacity(size_t required_size);
    void shift_buffer();
};

class PacketBufferPool {
public:
    explicit PacketBufferPool(size_t initial_count = 32, size_t max_count = 256);
    ~PacketBufferPool();
    
    std::unique_ptr<PacketBuffer> acquire_buffer(size_t min_size = PacketBuffer::DEFAULT_BUFFER_SIZE);
    void release_buffer(std::unique_ptr<PacketBuffer> buffer);
    
    size_t available_buffers() const;
    size_t total_buffers() const;
    
    void preallocate(size_t count, size_t buffer_size = PacketBuffer::DEFAULT_BUFFER_SIZE);
    void cleanup_oversized_buffers();

private:
    std::stack<std::unique_ptr<PacketBuffer>> small_buffers_;
    std::stack<std::unique_ptr<PacketBuffer>> large_buffers_;
    mutable std::mutex pool_mutex_;
    std::atomic<size_t> total_buffers_;
    size_t max_buffers_;
    
    static constexpr size_t LARGE_BUFFER_THRESHOLD = 32768;
};

class ConnectionContext {
public:
    ConnectionContext();
    ~ConnectionContext();
    
    void reset();
    
    std::string client_id;
    std::string remote_address;
    uint16_t remote_port;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_activity;
    
    std::unique_ptr<PacketBuffer> read_buffer;
    std::unique_ptr<PacketBuffer> write_buffer;
    
    std::atomic<uint64_t> bytes_received;
    std::atomic<uint64_t> bytes_sent;
    std::atomic<uint32_t> packets_received;
    std::atomic<uint32_t> packets_sent;
};

class ConnectionPool {
public:
    explicit ConnectionPool(size_t initial_size = 16, size_t max_size = 512);
    ~ConnectionPool();
    
    std::unique_ptr<ConnectionContext> acquire_connection();
    void release_connection(std::unique_ptr<ConnectionContext> context);
    
    size_t active_connections() const;
    size_t available_connections() const;
    
    void cleanup_expired_connections(std::chrono::seconds timeout);

private:
    ObjectPool<ConnectionContext> connection_pool_;
    PacketBufferPool buffer_pool_;
    std::atomic<size_t> active_count_;
};

class MemoryPoolManager {
public:
    static MemoryPoolManager& instance();
    
    PacketBufferPool& get_packet_pool();
    ConnectionPool& get_connection_pool();
    
    template<typename T>
    ObjectPool<T>& get_object_pool();
    
    void initialize_pools(size_t max_connections, size_t max_buffers);
    void shutdown_pools();
    
    struct MemoryStats {
        size_t total_packet_buffers;
        size_t available_packet_buffers;
        size_t active_connections;
        size_t available_connections;
        size_t total_memory_bytes;
    };
    
    MemoryStats get_memory_stats() const;

public:
    MemoryPoolManager();
    ~MemoryPoolManager();

private:
    
    std::unique_ptr<PacketBufferPool> packet_pool_;
    std::unique_ptr<ConnectionPool> connection_pool_;
    mutable std::mutex stats_mutex_;
    
    static std::unique_ptr<MemoryPoolManager> instance_;
    static std::once_flag init_flag_;
};

template<typename T>
class PooledAllocator {
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    
    template<typename U>
    struct rebind {
        using other = PooledAllocator<U>;
    };
    
    PooledAllocator() = default;
    
    template<typename U>
    PooledAllocator(const PooledAllocator<U>&) {}
    
    pointer allocate(size_type n);
    void deallocate(pointer p, size_type n);
    
    template<typename U, typename... Args>
    void construct(U* p, Args&&... args);
    
    template<typename U>
    void destroy(U* p);

private:
    static thread_local std::stack<void*> free_blocks_;
    static constexpr size_t BLOCK_SIZE = 4096;
};

class RAIIGuard {
public:
    template<typename Callable>
    explicit RAIIGuard(Callable&& cleanup) : cleanup_(std::forward<Callable>(cleanup)) {}
    
    ~RAIIGuard() {
        if (cleanup_) {
            cleanup_();
        }
    }
    
    RAIIGuard(const RAIIGuard&) = delete;
    RAIIGuard& operator=(const RAIIGuard&) = delete;
    
    RAIIGuard(RAIIGuard&& other) noexcept : cleanup_(std::move(other.cleanup_)) {
        other.cleanup_ = nullptr;
    }
    
    RAIIGuard& operator=(RAIIGuard&& other) noexcept {
        if (this != &other) {
            if (cleanup_) cleanup_();
            cleanup_ = std::move(other.cleanup_);
            other.cleanup_ = nullptr;
        }
        return *this;
    }

private:
    std::function<void()> cleanup_;
};

}

#include "memory_pool_manager.inl"
