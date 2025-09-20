#pragma once

#include "../domain/interfaces.h"
#include <random>
#include <unordered_map>
#include <mutex>

namespace seeded_vpn::infrastructure {

class SeededGenerator : public domain::ISeedGenerator {
public:
    SeededGenerator();
    
    domain::SeedValue generate(const domain::SeedContext& context) override;
    void set_strategy(domain::SeedStrategy strategy) override;
    void rotate_base_seed() override;
    bool validate_seed(domain::SeedValue seed) const override;

private:
    domain::SeedStrategy strategy_;
    domain::SeedValue base_seed_;
    uint32_t rotation_counter_;
    std::chrono::steady_clock::time_point last_rotation_;
    
    std::unordered_map<std::string, domain::SeedValue> client_seeds_;
    std::unordered_map<std::string, domain::SeedValue> domain_seeds_;
    
    mutable std::mutex mutex_;
    std::mt19937_64 rng_;
    
    domain::SeedValue generate_per_connection(const domain::SeedContext& context);
    domain::SeedValue generate_per_client(const domain::SeedContext& context);
    domain::SeedValue generate_per_time_window(const domain::SeedContext& context);
    domain::SeedValue generate_hybrid(const domain::SeedContext& context);
    
    uint64_t hash_context(const domain::SeedContext& context);
    bool should_rotate();
};

class IPv6AddressRepository : public domain::IIPv6AddressManager {
public:
    IPv6AddressRepository();
    
    domain::IPv6Address allocate(domain::SeedValue seed) override;
    void release(const domain::IPv6Address& address) override;
    bool is_available(const domain::IPv6Address& address) override;
    std::vector<domain::IPv6Address> get_active_addresses() override;
    bool expand_pool() override;
    size_t get_pool_size() const override;

private:
    std::string prefix_;
    std::unordered_map<std::string, bool> allocated_addresses_;
    mutable std::mutex mutex_;
    
    domain::IPv6Address seed_to_address(domain::SeedValue seed);
    std::string address_to_string(const domain::IPv6Address& address);
    bool is_valid_address(const domain::IPv6Address& address);
};

}
