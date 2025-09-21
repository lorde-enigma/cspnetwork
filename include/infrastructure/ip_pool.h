#pragma once

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <memory>
#include <mutex>
#include <chrono>
#include <optional>

namespace seeded_vpn::infrastructure {

struct IPRange {
    std::string network;
    std::string netmask;
    uint32_t start_ip;
    uint32_t end_ip;
    
    IPRange(const std::string& cidr);
    bool contains(uint32_t ip) const;
    uint32_t get_network_ip() const;
    uint32_t get_broadcast_ip() const;
    size_t get_available_count() const;
};

struct ClientIPAssignment {
    std::string client_id;
    std::string ip_address;
    uint32_t ip_numeric;
    std::chrono::system_clock::time_point assigned_at;
    std::chrono::system_clock::time_point last_activity;
    bool is_active;
    
    ClientIPAssignment(const std::string& id, uint32_t ip);
    bool is_expired(std::chrono::seconds timeout) const;
    void update_activity();
};

class IPPool {
public:
    explicit IPPool(const std::string& cidr_range);
    explicit IPPool(const std::vector<std::string>& cidr_ranges);
    
    ~IPPool() = default;
    
    // IP allocation and management
    std::optional<std::string> allocate_ip(const std::string& client_id);
    bool release_ip(const std::string& client_id);
    bool release_ip_by_address(const std::string& ip_address);
    
    // IP queries
    bool is_allocated(const std::string& ip_address) const;
    std::optional<std::string> get_client_ip(const std::string& client_id) const;
    std::optional<std::string> get_ip_client(const std::string& ip_address) const;
    
    // Pool statistics
    size_t get_total_ips() const;
    size_t get_allocated_count() const;
    size_t get_available_count() const;
    double get_utilization_percentage() const;
    
    // Client activity management
    bool update_client_activity(const std::string& client_id);
    void cleanup_expired_leases(std::chrono::seconds timeout = std::chrono::seconds{300});
    
    // Pool information
    std::vector<std::string> get_allocated_ips() const;
    std::vector<ClientIPAssignment> get_active_assignments() const;
    std::string get_pool_info() const;
    
    // Range management
    bool add_range(const std::string& cidr);
    std::vector<std::string> get_ranges() const;
    
    // Persistence (optional)
    bool save_to_file(const std::string& file_path) const;
    bool load_from_file(const std::string& file_path);

public:
    static bool is_valid_ip_format(const std::string& ip);
    static uint32_t ip_string_to_numeric(const std::string& ip);
    static std::string ip_numeric_to_string(uint32_t ip);

private:
    mutable std::mutex pool_mutex_;
    std::vector<std::unique_ptr<IPRange>> ip_ranges_;
    std::unordered_map<std::string, std::unique_ptr<ClientIPAssignment>> client_assignments_;
    std::unordered_map<uint32_t, std::string> ip_to_client_;
    std::unordered_set<uint32_t> allocated_ips_;
    
    // Internal methods
    uint32_t find_next_available_ip() const;
    bool is_ip_in_ranges(uint32_t ip) const;
    void add_range_internal(std::unique_ptr<IPRange> range);
    std::string format_assignment_info(const ClientIPAssignment& assignment) const;
    
    // IP conversion utilities
    static std::pair<uint32_t, uint32_t> parse_cidr_range(const std::string& cidr);
};

// IP utility functions
namespace ip_utils {
    bool is_private_ip(const std::string& ip);
    bool is_valid_cidr(const std::string& cidr);
    std::string get_network_address(const std::string& ip, const std::string& netmask);
    std::string get_broadcast_address(const std::string& ip, const std::string& netmask);
    uint32_t netmask_to_prefix_length(const std::string& netmask);
    std::string prefix_length_to_netmask(uint32_t prefix_length);
    std::vector<std::string> generate_ip_range(const std::string& start_ip, const std::string& end_ip);
}

// Default IP ranges for VPN use
namespace default_ranges {
    constexpr const char* VPN_RANGE_10 = "10.8.0.0/24";
    constexpr const char* VPN_RANGE_172 = "172.16.0.0/24";
    constexpr const char* VPN_RANGE_192 = "192.168.100.0/24";
    
    std::vector<std::string> get_safe_ranges();
    std::string get_recommended_range();
}

}
