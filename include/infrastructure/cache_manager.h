#pragma once

#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <functional>
#include <list>
#include <optional>
#include <atomic>
#include <thread>
#include <mutex>
#include <tuple>

namespace CipherProxy::Infrastructure {

template<typename Key, typename Value>
class LRUCache {
public:
    using KeyType = Key;
    using ValueType = Value;
    using TimePoint = std::chrono::steady_clock::time_point;
    using Duration = std::chrono::milliseconds;
    
    struct CacheEntry {
        Value value;
        TimePoint created_at;
        TimePoint last_accessed;
        std::atomic<uint64_t> access_count{0};
        
        CacheEntry(Value v) 
            : value(std::move(v)), 
              created_at(std::chrono::steady_clock::now()),
              last_accessed(std::chrono::steady_clock::now()) {}
              
        CacheEntry(const CacheEntry& other) 
            : value(other.value),
              created_at(other.created_at),
              last_accessed(other.last_accessed),
              access_count(other.access_count.load()) {}
              
        CacheEntry(CacheEntry&& other) noexcept
            : value(std::move(other.value)),
              created_at(other.created_at),
              last_accessed(other.last_accessed),
              access_count(other.access_count.load()) {}
              
        CacheEntry& operator=(const CacheEntry& other) {
            if (this != &other) {
                value = other.value;
                created_at = other.created_at;
                last_accessed = other.last_accessed;
                access_count.store(other.access_count.load());
            }
            return *this;
        }
        
        CacheEntry& operator=(CacheEntry&& other) noexcept {
            if (this != &other) {
                value = std::move(other.value);
                created_at = other.created_at;
                last_accessed = other.last_accessed;
                access_count.store(other.access_count.load());
            }
            return *this;
        }
    };
    
    LRUCache(size_t max_size, Duration ttl = Duration::max());
    ~LRUCache() = default;
    
    void put(const Key& key, Value value);
    std::optional<Value> get(const Key& key);
    bool contains(const Key& key) const;
    void remove(const Key& key);
    void clear();
    
    size_t size() const;
    size_t max_size() const;
    bool empty() const;
    
    void set_ttl(Duration ttl);
    void cleanup_expired();
    
    struct Stats {
        uint64_t hits = 0;
        uint64_t misses = 0;
        uint64_t evictions = 0;
        uint64_t expired_cleanups = 0;
        double hit_ratio() const { return hits + misses > 0 ? static_cast<double>(hits) / (hits + misses) : 0.0; }
    };
    
    Stats get_stats() const;
    void reset_stats();

private:
    using ListIterator = typename std::list<Key>::iterator;
    
    mutable std::shared_mutex mutex_;
    std::unordered_map<Key, std::pair<CacheEntry, ListIterator>> cache_;
    std::list<Key> access_order_;
    size_t max_size_;
    Duration ttl_;
    
    mutable std::atomic<uint64_t> hits_{0};
    mutable std::atomic<uint64_t> misses_{0};
    mutable std::atomic<uint64_t> evictions_{0};
    mutable std::atomic<uint64_t> expired_cleanups_{0};
    
    void evict_lru();
    bool is_expired(const CacheEntry& entry) const;
    void touch(const Key& key, typename decltype(cache_)::iterator it);
};

class ConnectionCache {
public:
    struct ConnectionInfo {
        std::string remote_address;
        uint16_t remote_port;
        std::chrono::steady_clock::time_point created_at;
        std::chrono::steady_clock::time_point last_used;
        uint64_t request_count{0};
        bool is_active;
        std::string session_id;
    };
    
    ConnectionCache(size_t max_connections = 1000, 
                   std::chrono::minutes connection_ttl = std::chrono::minutes(30));
    
    void add_connection(const std::string& client_id, ConnectionInfo info);
    std::optional<ConnectionInfo> get_connection(const std::string& client_id);
    bool has_active_connection(const std::string& client_id);
    void mark_connection_inactive(const std::string& client_id);
    void remove_connection(const std::string& client_id);
    
    void cleanup_inactive_connections();
    size_t get_active_connection_count() const;
    std::vector<std::string> get_active_clients() const;

private:
    LRUCache<std::string, ConnectionInfo> cache_;
    mutable std::shared_mutex mutex_;
};

class RouteCache {
public:
    struct RouteInfo {
        std::string target_server;
        std::vector<std::string> available_servers;
        std::chrono::steady_clock::time_point cached_at;
        uint32_t load_factor;
        double latency_ms;
        bool is_healthy;
    };
    
    RouteCache(size_t max_routes = 10000,
               std::chrono::minutes route_ttl = std::chrono::minutes(10));
    
    void cache_route(const std::string& destination, RouteInfo info);
    std::optional<RouteInfo> get_route(const std::string& destination);
    void invalidate_route(const std::string& destination);
    void update_server_health(const std::string& server, bool is_healthy);
    
    void cleanup_stale_routes();
    size_t get_cached_route_count() const;

private:
    LRUCache<std::string, RouteInfo> cache_;
    mutable std::shared_mutex mutex_;
};

class DNSCache {
public:
    struct DNSRecord {
        std::vector<std::string> ip_addresses;
        std::chrono::steady_clock::time_point resolved_at;
        std::chrono::seconds ttl;
        std::string record_type;
    };
    
    DNSCache(size_t max_records = 5000,
             std::chrono::minutes default_ttl = std::chrono::minutes(5));
    
    void cache_dns_record(const std::string& hostname, DNSRecord record);
    std::optional<DNSRecord> resolve_hostname(const std::string& hostname);
    void invalidate_hostname(const std::string& hostname);
    void cleanup_expired_records();
    
    size_t get_record_count() const;
    double get_hit_ratio() const;

private:
    LRUCache<std::string, DNSRecord> cache_;
    mutable std::shared_mutex mutex_;
};

class SessionCache {
public:
    struct SessionData {
        std::string session_id;
        std::string client_id;
        std::vector<uint8_t> session_key;
        std::chrono::steady_clock::time_point created_at;
        std::chrono::steady_clock::time_point expires_at;
        std::unordered_map<std::string, std::string> attributes;
        bool is_authenticated;
    };
    
    SessionCache(size_t max_sessions = 50000,
                 std::chrono::hours session_ttl = std::chrono::hours(24));
    
    void create_session(const std::string& session_id, SessionData data);
    std::optional<SessionData> get_session(const std::string& session_id);
    bool validate_session(const std::string& session_id);
    void invalidate_session(const std::string& session_id);
    void extend_session(const std::string& session_id, std::chrono::minutes extension);
    
    void cleanup_expired_sessions();
    size_t get_active_session_count() const;
    std::vector<std::string> get_sessions_for_client(const std::string& client_id) const;

private:
    LRUCache<std::string, SessionData> cache_;
    mutable std::shared_mutex mutex_;
};

class CacheManager {
public:
    static CacheManager& instance();
    
    void initialize();
    void shutdown();
    
    ConnectionCache& get_connection_cache();
    RouteCache& get_route_cache();
    DNSCache& get_dns_cache();
    SessionCache& get_session_cache();
    
    struct GlobalCacheStats {
        size_t total_cached_items;
        double overall_hit_ratio;
        size_t memory_usage_estimate;
        std::chrono::steady_clock::time_point last_cleanup;
    };
    
    GlobalCacheStats get_global_stats() const;
    void cleanup_all_caches();
    void clear_all_caches();
    
    void set_cleanup_interval(std::chrono::minutes interval);
    void start_background_cleanup();
    void stop_background_cleanup();

private:
    CacheManager() = default;
    
    std::unique_ptr<ConnectionCache> connection_cache_;
    std::unique_ptr<RouteCache> route_cache_;
    std::unique_ptr<DNSCache> dns_cache_;
    std::unique_ptr<SessionCache> session_cache_;
    
    std::atomic<bool> initialized_{false};
    std::atomic<bool> cleanup_running_{false};
    std::thread cleanup_thread_;
    std::chrono::minutes cleanup_interval_{5};
    
    void cleanup_loop();
};

template<typename Key, typename Value>
class ThreadSafeCache {
public:
    using CacheFunction = std::function<Value(const Key&)>;
    
    ThreadSafeCache(size_t max_size, std::chrono::milliseconds ttl = std::chrono::milliseconds::max());
    
    Value get_or_compute(const Key& key, CacheFunction compute_func);
    void put(const Key& key, Value value);
    std::optional<Value> get(const Key& key);
    void remove(const Key& key);
    void clear();
    
    size_t size() const;
    bool empty() const;
    double hit_ratio() const;

private:
    LRUCache<Key, Value> cache_;
    mutable std::shared_mutex compute_mutex_;
};

class PerformanceOptimizer {
public:
    static PerformanceOptimizer& instance();
    
    void optimize_caches();
    void tune_cache_sizes();
    void analyze_cache_patterns();
    
    struct CacheRecommendations {
        size_t recommended_connection_cache_size;
        size_t recommended_route_cache_size;
        size_t recommended_dns_cache_size;
        size_t recommended_session_cache_size;
        std::chrono::minutes recommended_cleanup_interval;
        std::string optimization_notes;
    };
    
    CacheRecommendations get_recommendations() const;
    void apply_recommendations(const CacheRecommendations& recommendations);

private:
    PerformanceOptimizer() = default;
    
    void analyze_cache_utilization();
    void optimize_cache_algorithms();
    void tune_ttl_values();
};

}

#include "cache_manager.inl"
