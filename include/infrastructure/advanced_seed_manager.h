#pragma once

#include "domain/interfaces.h"
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <chrono>

namespace seeded_vpn::infrastructure {

enum class AdvancedSeedStrategy {
    PER_CONNECTION,
    PER_CLIENT, 
    PER_TIME_WINDOW,
    HYBRID,
    PER_DOMAIN,
    GEOGRAPHIC_BASED,
    LOAD_BALANCED
};

struct ExtendedSeedContext {
    std::string client_id;
    std::string connection_id;
    std::string domain_hint;
    std::string geographic_region;
    std::chrono::system_clock::time_point timestamp;
    uint32_t load_factor;
    std::string certificate_fingerprint;
};

class AdvancedSeedGenerator : public domain::ISeedGenerator {
public:
    AdvancedSeedGenerator();
    
    domain::SeedValue generate(const domain::SeedContext& context) override;
    void set_strategy(domain::SeedStrategy strategy) override;
    void rotate_base_seed() override;
    
    void set_advanced_strategy(AdvancedSeedStrategy strategy);
    void set_time_window_duration(std::chrono::minutes duration);
    void set_geographic_regions(const std::vector<std::string>& regions);
    void update_load_factors(const std::unordered_map<std::string, uint32_t>& factors);

private:
    AdvancedSeedStrategy advanced_strategy_;
    std::chrono::minutes time_window_duration_{30};
    std::vector<std::string> geographic_regions_;
    std::unordered_map<std::string, uint32_t> load_factors_;
    
    domain::SeedStrategy strategy_;
    domain::SeedValue base_seed_;
    uint32_t rotation_counter_;
    std::chrono::steady_clock::time_point last_rotation_;
    
    std::unordered_map<std::string, domain::SeedValue> client_seeds_;
    std::unordered_map<std::string, domain::SeedValue> domain_seeds_;
    std::unordered_map<std::string, domain::SeedValue> geographic_seeds_;
    std::unordered_map<std::string, domain::SeedValue> time_window_seeds_;
    
    mutable std::mutex mutex_;
    std::mt19937_64 rng_;
    
    domain::SeedValue generate_per_connection(const ExtendedSeedContext& context);
    domain::SeedValue generate_per_client(const ExtendedSeedContext& context);
    domain::SeedValue generate_per_time_window(const ExtendedSeedContext& context);
    domain::SeedValue generate_hybrid(const ExtendedSeedContext& context);
    domain::SeedValue generate_per_domain(const ExtendedSeedContext& context);
    domain::SeedValue generate_geographic_based(const ExtendedSeedContext& context);
    domain::SeedValue generate_load_balanced(const ExtendedSeedContext& context);
    
    ExtendedSeedContext extend_context(const domain::SeedContext& context);
    uint64_t hash_extended_context(const ExtendedSeedContext& context);
    std::string get_time_window_key(const std::chrono::system_clock::time_point& time);
    bool should_rotate();
};

class IPv6PoolManager : public domain::IIPv6AddressManager {
public:
    IPv6PoolManager(const std::string& ipv6_prefix, size_t pool_size = 10000);
    
    domain::IPv6Address allocate(domain::SeedValue seed) override;
    void release(const domain::IPv6Address& address) override;
    bool is_available(const domain::IPv6Address& address) override;
    std::vector<domain::IPv6Address> get_active_addresses() override;
    bool expand_pool() override;
    size_t get_pool_size() const override;
    
    void expand_pool(size_t additional_size);
    void compact_pool();
    size_t get_pool_utilization() const;
    size_t get_total_pool_size() const;

private:
    std::string prefix_;
    size_t pool_size_;
    std::unordered_map<std::string, bool> allocated_addresses_;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> allocation_times_;
    std::unordered_set<std::string> reserved_addresses_;
    
    mutable std::mutex mutex_;
    
    domain::IPv6Address seed_to_address(domain::SeedValue seed);
    std::string address_to_string(const domain::IPv6Address& address);
    domain::IPv6Address string_to_address(const std::string& addr_str);
    bool is_valid_address(const domain::IPv6Address& address);
    bool is_in_pool_range(const domain::IPv6Address& address);
    void cleanup_expired_allocations();
};

}
