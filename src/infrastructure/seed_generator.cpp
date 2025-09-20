#include "../include/infrastructure/seed_generator.h"
#include <chrono>
#include <functional>
#include <sstream>
#include <iomanip>
#include <regex>

namespace seeded_vpn::infrastructure {

SeededGenerator::SeededGenerator()
    : strategy_(domain::SeedStrategy::PER_CONNECTION)
    , base_seed_(std::random_device{}())
    , rotation_counter_(0)
    , last_rotation_(std::chrono::steady_clock::now())
    , rng_(base_seed_) {
}

domain::SeedValue SeededGenerator::generate(const domain::SeedContext& context) {
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

void SeededGenerator::set_strategy(domain::SeedStrategy strategy) {
    std::lock_guard<std::mutex> lock(mutex_);
    strategy_ = strategy;
}

void SeededGenerator::rotate_base_seed() {
    base_seed_ = rng_();
    rotation_counter_++;
    last_rotation_ = std::chrono::steady_clock::now();
    client_seeds_.clear();
    domain_seeds_.clear();
}

domain::SeedValue SeededGenerator::generate_per_connection(const domain::SeedContext& context) {
    uint64_t context_hash = hash_context(context);
    return base_seed_ ^ context_hash ^ context.connection_id;
}

domain::SeedValue SeededGenerator::generate_per_client(const domain::SeedContext& context) {
    auto it = client_seeds_.find(context.client_id);
    if (it != client_seeds_.end()) {
        return it->second;
    }
    
    std::hash<std::string> hasher;
    domain::SeedValue client_seed = base_seed_ ^ hasher(context.client_id);
    client_seeds_[context.client_id] = client_seed;
    return client_seed;
}

domain::SeedValue SeededGenerator::generate_per_time_window(const domain::SeedContext& context) {
    auto now = std::chrono::steady_clock::now();
    auto time_window = std::chrono::duration_cast<std::chrono::minutes>(now.time_since_epoch()).count() / 5;
    return base_seed_ ^ static_cast<uint64_t>(time_window) ^ context.connection_id;
}

domain::SeedValue SeededGenerator::generate_hybrid(const domain::SeedContext& context) {
    domain::SeedValue client_part = generate_per_client(context);
    domain::SeedValue time_part = generate_per_time_window(context);
    domain::SeedValue connection_part = generate_per_connection(context);
    
    return client_part ^ (time_part << 16) ^ (connection_part << 32);
}

uint64_t SeededGenerator::hash_context(const domain::SeedContext& context) {
    std::hash<std::string> str_hasher;
    std::hash<uint64_t> int_hasher;
    
    uint64_t client_hash = str_hasher(context.client_id);
    uint64_t connection_hash = int_hasher(context.connection_id);
    
    return client_hash ^ connection_hash;
}

bool SeededGenerator::should_rotate() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - last_rotation_);
    return elapsed.count() >= 60;
}

bool SeededGenerator::validate_seed(domain::SeedValue seed) const {
    return seed != 0;
}

IPv6AddressRepository::IPv6AddressRepository()
    : prefix_("10.8.0.0/24") {
}

domain::IPv6Address IPv6AddressRepository::allocate(domain::SeedValue seed) {
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

void IPv6AddressRepository::release(const domain::IPv6Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string addr_str = address_to_string(address);
    allocated_addresses_[addr_str] = false;
}

bool IPv6AddressRepository::is_available(const domain::IPv6Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string addr_str = address_to_string(address);
    return !allocated_addresses_[addr_str];
}

std::vector<domain::IPv6Address> IPv6AddressRepository::get_active_addresses() {
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

domain::IPv6Address IPv6AddressRepository::seed_to_address(domain::SeedValue seed) {
    std::array<uint8_t, 16> addr = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    uint64_t seed_high = seed >> 32;
    uint64_t seed_low = seed & 0xFFFFFFFF;
    
    addr[8] = static_cast<uint8_t>((seed_high >> 24) & 0xFF);
    addr[9] = static_cast<uint8_t>((seed_high >> 16) & 0xFF);
    addr[10] = static_cast<uint8_t>((seed_high >> 8) & 0xFF);
    addr[11] = static_cast<uint8_t>(seed_high & 0xFF);
    addr[12] = static_cast<uint8_t>((seed_low >> 24) & 0xFF);
    addr[13] = static_cast<uint8_t>((seed_low >> 16) & 0xFF);
    addr[14] = static_cast<uint8_t>((seed_low >> 8) & 0xFF);
    addr[15] = static_cast<uint8_t>(seed_low & 0xFF);
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        uint16_t word = (static_cast<uint16_t>(addr[i]) << 8) | addr[i + 1];
        oss << std::setw(4) << word;
    }
    
    return oss.str();
}

std::string IPv6AddressRepository::address_to_string(const domain::IPv6Address& address) {
    return address;
}

bool IPv6AddressRepository::is_valid_address(const domain::IPv6Address& address) {
    if (address.empty()) return false;
    
    std::regex ipv6_pattern(R"(^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$)");
    return std::regex_match(address, ipv6_pattern) && address.find("fd00:") == 0;
}

bool IPv6AddressRepository::expand_pool() {
    return true;
}

size_t IPv6AddressRepository::get_pool_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return allocated_addresses_.size();
}

}
