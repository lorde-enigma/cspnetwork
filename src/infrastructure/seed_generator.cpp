#include "infrastructure/seed_generator.h"
#include <chrono>
#include <functional>
#include <sstream>
#include <iomanip>

namespace seeded_vpn::infrastructure {

CryptoSeedGenerator::CryptoSeedGenerator()
    : strategy_(domain::SeedStrategy::PER_CONNECTION)
    , base_seed_(std::random_device{}())
    , rotation_counter_(0)
    , last_rotation_(std::chrono::steady_clock::now())
    , rng_(base_seed_) {
}

domain::SeedValue CryptoSeedGenerator::generate(const domain::SeedContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (should_rotate()) {
        rotate_base_seed();
    }
    
    switch (strategy_) {
        case domain::SeedStrategy::PER_CONNECTION:
            return generate_per_connection(context);
        case domain::SeedStrategy::PER_CLIENT:
            return generate_per_client(context);
        case domain::SeedStrategy::PER_TIME_WINDOW:
            return generate_per_time_window(context);
        case domain::SeedStrategy::HYBRID:
            return generate_hybrid(context);
    }
    return generate_per_connection(context);
}

void CryptoSeedGenerator::set_strategy(domain::SeedStrategy strategy) {
    std::lock_guard<std::mutex> lock(mutex_);
    strategy_ = strategy;
}

void CryptoSeedGenerator::rotate_base_seed() {
    base_seed_ = rng_();
    rotation_counter_++;
    last_rotation_ = std::chrono::steady_clock::now();
    client_seeds_.clear();
    domain_seeds_.clear();
}

domain::SeedValue CryptoSeedGenerator::generate_per_connection(const domain::SeedContext& context) {
    uint64_t context_hash = hash_context(context);
    return base_seed_ ^ context_hash ^ context.connection_id;
}

domain::SeedValue CryptoSeedGenerator::generate_per_client(const domain::SeedContext& context) {
    auto it = client_seeds_.find(context.client_id);
    if (it != client_seeds_.end()) {
        return it->second;
    }
    
    std::hash<std::string> hasher;
    domain::SeedValue client_seed = base_seed_ ^ hasher(context.client_id);
    client_seeds_[context.client_id] = client_seed;
    return client_seed;
}

domain::SeedValue CryptoSeedGenerator::generate_per_time_window(const domain::SeedContext& context) {
    auto now = std::chrono::steady_clock::now();
    auto time_window = std::chrono::duration_cast<std::chrono::minutes>(now.time_since_epoch()).count() / 5;
    return base_seed_ ^ static_cast<uint64_t>(time_window) ^ context.connection_id;
}

domain::SeedValue CryptoSeedGenerator::generate_hybrid(const domain::SeedContext& context) {
    domain::SeedValue client_part = generate_per_client(context);
    domain::SeedValue time_part = generate_per_time_window(context);
    domain::SeedValue connection_part = generate_per_connection(context);
    
    return client_part ^ (time_part << 16) ^ (connection_part << 32);
}

uint64_t CryptoSeedGenerator::hash_context(const domain::SeedContext& context) {
    std::hash<std::string> str_hasher;
    std::hash<uint64_t> int_hasher;
    
    uint64_t client_hash = str_hasher(context.client_id);
    uint64_t connection_hash = int_hasher(context.connection_id);
    
    return client_hash ^ connection_hash;
}

bool CryptoSeedGenerator::should_rotate() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - last_rotation_);
    return elapsed.count() >= 60;
}

bool CryptoSeedGenerator::validate_seed(domain::SeedValue seed) const {
    return seed != 0;
}

IPv6AddressManager::IPv6AddressManager(const std::string& ipv6_prefix)
    : prefix_(ipv6_prefix) {
}

domain::IPv6Address IPv6AddressManager::allocate(domain::SeedValue seed) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    domain::IPv6Address address = seed_to_address(seed);
    std::string addr_str = address_to_string(address);
    
    if (allocated_addresses_[addr_str]) {
        seed ^= std::hash<uint64_t>{}(seed);
        address = seed_to_address(seed);
        addr_str = address_to_string(address);
    }
    
    allocated_addresses_[addr_str] = true;
    return address;
}

void IPv6AddressManager::release(const domain::IPv6Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string addr_str = address_to_string(address);
    allocated_addresses_[addr_str] = false;
}

bool IPv6AddressManager::is_available(const domain::IPv6Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string addr_str = address_to_string(address);
    return !allocated_addresses_[addr_str];
}

std::vector<domain::IPv6Address> IPv6AddressManager::get_active_addresses() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<domain::IPv6Address> active;
    
    for (const auto& pair : allocated_addresses_) {
        if (pair.second) {
            domain::IPv6Address addr{};
            active.push_back(addr);
        }
    }
    
    return active;
}

domain::IPv6Address IPv6AddressManager::seed_to_address(domain::SeedValue seed) {
    domain::IPv6Address address{};
    
    address[0] = 0x20;
    address[1] = 0x01;
    address[2] = 0x0d;
    address[3] = 0xb8;
    
    for (int i = 4; i < 16; ++i) {
        address[i] = static_cast<uint8_t>((seed >> ((i - 4) * 8)) & 0xFF);
    }
    
    return address;
}

std::string IPv6AddressManager::address_to_string(const domain::IPv6Address& address) {
    std::stringstream ss;
    ss << std::hex;
    
    for (size_t i = 0; i < address.size(); i += 2) {
        if (i > 0) ss << ":";
        ss << std::setfill('0') << std::setw(2) << static_cast<int>(address[i])
           << std::setfill('0') << std::setw(2) << static_cast<int>(address[i + 1]);
    }
    
    return ss.str();
}

bool IPv6AddressManager::is_valid_address(const domain::IPv6Address& address) {
    return address[0] != 0 || address[1] != 0;
}

bool IPv6AddressManager::expand_pool() {
    return true;
}

size_t IPv6AddressManager::get_pool_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return allocated_addresses_.size();
}

}
