#pragma once

#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include "domain/types.h"
#include "infrastructure/advanced_seed_manager.h"

namespace seeded_vpn::infrastructure {

enum class LoadBalanceStrategy {
    ROUND_ROBIN,
    WEIGHTED,
    LEAST_CONNECTIONS,
    HEALTH_BASED
};

enum class RouteStatus {
    ACTIVE,
    DEGRADED,
    FAILED,
    MAINTENANCE
};

struct RouteHealth {
    RouteStatus status;
    double success_rate;
    uint64_t total_packets;
    uint64_t failed_packets;
    std::chrono::steady_clock::time_point last_success;
    std::chrono::steady_clock::time_point last_failure;
    uint32_t consecutive_failures;
};

struct TrafficMetrics {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    double avg_latency_ms;
    std::chrono::steady_clock::time_point last_activity;
};

struct LoadBalanceTarget {
    std::string address;
    uint32_t weight;
    RouteHealth health;
    TrafficMetrics metrics;
    bool is_available;
};

class SeededRoute {
private:
    std::string route_id_;
    std::vector<std::string> seeded_addresses_;
    size_t current_address_index_;
    RouteHealth health_;
    TrafficMetrics metrics_;
    mutable std::mutex route_mutex_;

public:
    explicit SeededRoute(const std::string& route_id, const std::vector<std::string>& addresses);
    
    std::string get_current_address();
    std::string get_next_address();
    bool try_fallback_address();
    
    void report_success(size_t bytes_transferred, double latency_ms);
    void report_failure();
    
    RouteHealth get_health() const;
    TrafficMetrics get_metrics() const;
    
    bool is_healthy() const;
    void reset_health();
    
    void add_seeded_address(const std::string& address);
    void remove_seeded_address(const std::string& address);
    
    size_t get_address_count() const;
    std::vector<std::string> get_all_addresses() const;
};

class LoadBalancer {
private:
    std::vector<LoadBalanceTarget> targets_;
    LoadBalanceStrategy strategy_;
    std::atomic<size_t> round_robin_index_;
    mutable std::mutex targets_mutex_;
    
    double total_weight_;
    bool use_weighted_balancing_;

    size_t select_weighted_target();
    size_t select_least_connections_target();
    size_t select_health_based_target();

public:
    LoadBalancer();
    
    void add_target(const std::string& address, uint32_t weight = 1);
    void remove_target(const std::string& address);
    
    std::optional<std::string> get_next_target();
    std::optional<std::string> get_best_available_target();
    
    void report_target_success(const std::string& address, size_t bytes, double latency);
    void report_target_failure(const std::string& address);
    
    void enable_weighted_balancing(bool enable);
    void update_target_weight(const std::string& address, uint32_t weight);
    
    std::vector<LoadBalanceTarget> get_target_status() const;
    size_t get_available_target_count() const;
    void cleanup_failed_targets();
    void reset_all_metrics();
};

class NAT66Table {
private:
    struct NAT66Entry {
        std::string internal_addr;
        std::string external_addr;
        uint16_t internal_port;
        uint16_t external_port;
        std::chrono::steady_clock::time_point last_activity;
        uint64_t bytes_transferred;
        bool is_persistent;
    };
    
    std::unordered_map<std::string, NAT66Entry> active_sessions_;
    std::unordered_map<std::string, uint16_t> port_allocations_;
    
    mutable std::mutex nat_mutex_;
    uint16_t next_port_;
    uint16_t port_range_start_;
    uint16_t port_range_end_;
    
    std::chrono::seconds session_timeout_;

    std::string generate_session_key(const std::string& internal_addr, uint16_t internal_port);
    uint16_t allocate_external_port();
    void release_external_port(uint16_t port);

public:
    explicit NAT66Table(uint16_t port_start = 32768, uint16_t port_end = 65535, 
                        std::chrono::seconds timeout = std::chrono::seconds(300));
    
    bool create_mapping(const std::string& internal_addr, uint16_t internal_port,
                       const std::string& external_addr, uint16_t& external_port);
    
    bool translate_outbound(const std::string& internal_addr, uint16_t internal_port,
                           std::string& external_addr, uint16_t& external_port);
    
    bool translate_inbound(const std::string& external_addr, uint16_t external_port,
                          std::string& internal_addr, uint16_t& internal_port);
    
    void update_session_activity(const std::string& internal_addr, uint16_t internal_port, size_t bytes);
    
    void cleanup_expired_sessions();
    void remove_session(const std::string& internal_addr, uint16_t internal_port);
    
    size_t get_active_session_count() const;
    std::vector<NAT66Entry> get_session_list() const;
    
    void set_session_timeout(std::chrono::seconds timeout);
    void enable_persistent_sessions(bool enable);
};

class TrafficMonitor {
private:
    struct ClientMetrics {
        uint64_t bytes_in;
        uint64_t bytes_out;
        uint64_t packets_in;
        uint64_t packets_out;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_activity;
        double avg_bandwidth_mbps;
    };
    
    std::unordered_map<std::string, ClientMetrics> client_metrics_;
    mutable std::mutex monitor_mutex_;
    
    std::atomic<uint64_t> total_bytes_processed_;
    std::atomic<uint64_t> total_packets_processed_;
    std::chrono::steady_clock::time_point monitor_start_time_;

public:
    TrafficMonitor();
    
    void record_traffic(const std::string& client_id, size_t bytes_in, size_t bytes_out,
                       size_t packets_in = 1, size_t packets_out = 1);
    
    ClientMetrics get_client_metrics(const std::string& client_id) const;
    std::vector<std::pair<std::string, ClientMetrics>> get_all_metrics() const;
    
    uint64_t get_total_bytes() const;
    uint64_t get_total_packets() const;
    double get_overall_bandwidth_mbps() const;
    
    std::vector<std::string> get_top_bandwidth_clients(size_t count = 10) const;
    std::vector<std::string> get_inactive_clients(std::chrono::seconds threshold) const;
    
    void reset_client_metrics(const std::string& client_id);
    void reset_all_metrics();
    
    void cleanup_old_clients(std::chrono::seconds threshold);
};

class SeededRouter {
private:
    std::unique_ptr<AdvancedSeedGenerator> seed_generator_;
    std::unique_ptr<IPv6PoolManager> pool_manager_;
    std::unique_ptr<LoadBalancer> load_balancer_;
    std::unique_ptr<NAT66Table> nat_table_;
    std::unique_ptr<TrafficMonitor> traffic_monitor_;
    
    std::unordered_map<std::string, std::unique_ptr<SeededRoute>> client_routes_;
    mutable std::mutex router_mutex_;
    
    std::atomic<bool> failover_enabled_;
    std::atomic<size_t> max_routes_per_client_;

    bool create_seeded_route_for_client(const std::string& client_id);
    std::vector<std::string> generate_route_addresses(const std::string& client_id, size_t count = 3);

public:
    explicit SeededRouter(std::unique_ptr<AdvancedSeedGenerator> seed_generator,
                         std::unique_ptr<IPv6PoolManager> pool_manager);
    ~SeededRouter();
    
    bool route_packet(const std::string& client_id, const std::vector<uint8_t>& packet,
                     std::string& destination_address);
    
    bool setup_client_routing(const std::string& client_id, const domain::SeedContext& context);
    void remove_client_routing(const std::string& client_id);
    
    void add_load_balance_target(const std::string& address, uint32_t weight = 1);
    void remove_load_balance_target(const std::string& address);
    
    void report_route_success(const std::string& client_id, size_t bytes, double latency);
    void report_route_failure(const std::string& client_id);
    
    std::optional<std::string> get_best_route_for_client(const std::string& client_id);
    std::vector<std::string> get_all_routes_for_client(const std::string& client_id);
    
    TrafficMetrics get_client_traffic_metrics(const std::string& client_id) const;
    std::vector<LoadBalanceTarget> get_load_balance_status() const;
    
    size_t get_active_route_count() const;
    size_t get_nat_session_count() const;
    
    void enable_failover(bool enable);
    void set_max_routes_per_client(size_t max_routes);
    
    void cleanup_inactive_routes(std::chrono::seconds threshold);
    void reset_route_metrics();
    
    bool create_nat_mapping(const std::string& client_id, const std::string& internal_addr, 
                           uint16_t internal_port, std::string& external_addr, uint16_t& external_port);
    
    void update_route_health();
    void perform_maintenance();
};

}
