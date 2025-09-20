#include "infrastructure/advanced_seed_manager.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

namespace seeded_vpn::infrastructure {

AdvancedSeedGenerator::AdvancedSeedGenerator() 
    : advanced_strategy_(AdvancedSeedStrategy::HYBRID)
    , strategy_(domain::SeedStrategy::HYBRID)
    , rotation_counter_(0)
    , last_rotation_(std::chrono::steady_clock::now())
    , rng_(std::random_device{}()) {
    
    std::random_device rd;
    base_seed_ = (static_cast<uint64_t>(rd()) << 32) | rd();
}

domain::SeedValue AdvancedSeedGenerator::generate(const domain::SeedContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (should_rotate()) {
        rotate_base_seed();
    }
    
    auto extended_context = extend_context(context);
    
    switch (advanced_strategy_) {
        case AdvancedSeedStrategy::PER_CONNECTION:
            return generate_per_connection(extended_context);
        case AdvancedSeedStrategy::PER_CLIENT:
            return generate_per_client(extended_context);
        case AdvancedSeedStrategy::PER_TIME_WINDOW:
            return generate_per_time_window(extended_context);
        case AdvancedSeedStrategy::HYBRID:
            return generate_hybrid(extended_context);
        case AdvancedSeedStrategy::PER_DOMAIN:
            return generate_per_domain(extended_context);
        case AdvancedSeedStrategy::GEOGRAPHIC_BASED:
            return generate_geographic_based(extended_context);
        case AdvancedSeedStrategy::LOAD_BALANCED:
            return generate_load_balanced(extended_context);
        default:
            return generate_hybrid(extended_context);
    }
}

void AdvancedSeedGenerator::set_strategy(domain::SeedStrategy strategy) {
    std::lock_guard<std::mutex> lock(mutex_);
    strategy_ = strategy;
}

void AdvancedSeedGenerator::rotate_base_seed() {
    std::random_device rd;
    base_seed_ = (static_cast<uint64_t>(rd()) << 32) | rd();
    rotation_counter_++;
    last_rotation_ = std::chrono::steady_clock::now();
}

void AdvancedSeedGenerator::set_advanced_strategy(AdvancedSeedStrategy strategy) {
    std::lock_guard<std::mutex> lock(mutex_);
    advanced_strategy_ = strategy;
}

void AdvancedSeedGenerator::set_time_window_duration(std::chrono::minutes duration) {
    std::lock_guard<std::mutex> lock(mutex_);
    time_window_duration_ = duration;
}

void AdvancedSeedGenerator::set_geographic_regions(const std::vector<std::string>& regions) {
    std::lock_guard<std::mutex> lock(mutex_);
    geographic_regions_ = regions;
}

void AdvancedSeedGenerator::update_load_factors(const std::unordered_map<std::string, uint32_t>& factors) {
    std::lock_guard<std::mutex> lock(mutex_);
    load_factors_ = factors;
}

domain::SeedValue AdvancedSeedGenerator::generate_per_connection(const ExtendedSeedContext& context) {
    auto hash = hash_extended_context(context);
    return base_seed_ ^ hash ^ rotation_counter_;
}

domain::SeedValue AdvancedSeedGenerator::generate_per_client(const ExtendedSeedContext& context) {
    auto it = client_seeds_.find(context.client_id);
    if (it != client_seeds_.end()) {
        return it->second;
    }
    
    auto hash = std::hash<std::string>{}(context.client_id + context.certificate_fingerprint);
    auto seed = base_seed_ ^ hash;
    client_seeds_[context.client_id] = seed;
    return seed;
}

domain::SeedValue AdvancedSeedGenerator::generate_per_time_window(const ExtendedSeedContext& context) {
    auto window_key = get_time_window_key(context.timestamp);
    
    auto it = time_window_seeds_.find(window_key);
    if (it != time_window_seeds_.end()) {
        return it->second;
    }
    
    auto hash = std::hash<std::string>{}(window_key);
    auto seed = base_seed_ ^ hash ^ rotation_counter_;
    time_window_seeds_[window_key] = seed;
    
    if (time_window_seeds_.size() > 100) {
        time_window_seeds_.erase(time_window_seeds_.begin());
    }
    
    return seed;
}

domain::SeedValue AdvancedSeedGenerator::generate_hybrid(const ExtendedSeedContext& context) {
    auto connection_seed = generate_per_connection(context);
    auto client_seed = generate_per_client(context);
    auto time_seed = generate_per_time_window(context);
    
    return (connection_seed ^ client_seed ^ time_seed) + 
           (context.load_factor << 16) + 
           std::hash<std::string>{}(context.geographic_region);
}

domain::SeedValue AdvancedSeedGenerator::generate_per_domain(const ExtendedSeedContext& context) {
    auto it = domain_seeds_.find(context.domain_hint);
    if (it != domain_seeds_.end()) {
        return it->second;
    }
    
    auto hash = std::hash<std::string>{}(context.domain_hint);
    auto seed = base_seed_ ^ hash;
    domain_seeds_[context.domain_hint] = seed;
    return seed;
}

domain::SeedValue AdvancedSeedGenerator::generate_geographic_based(const ExtendedSeedContext& context) {
    auto it = geographic_seeds_.find(context.geographic_region);
    if (it != geographic_seeds_.end()) {
        return it->second;
    }
    
    auto region_index = std::find(geographic_regions_.begin(), geographic_regions_.end(), 
                                  context.geographic_region) - geographic_regions_.begin();
    
    auto seed = base_seed_ ^ (region_index << 24) ^ std::hash<std::string>{}(context.geographic_region);
    geographic_seeds_[context.geographic_region] = seed;
    return seed;
}

domain::SeedValue AdvancedSeedGenerator::generate_load_balanced(const ExtendedSeedContext& context) {
    auto base = generate_per_client(context);
    auto load_it = load_factors_.find(context.client_id);
    uint32_t load_factor = load_it != load_factors_.end() ? load_it->second : 100;
    
    return base ^ (load_factor << 8) ^ (context.load_factor << 16);
}

ExtendedSeedContext AdvancedSeedGenerator::extend_context(const domain::SeedContext& context) {
    ExtendedSeedContext extended;
    extended.client_id = context.client_id;
    extended.connection_id = context.connection_id;
    extended.timestamp = std::chrono::system_clock::now();
    extended.domain_hint = context.client_id.substr(0, context.client_id.find('@'));
    extended.geographic_region = "default";
    extended.load_factor = 100;
    extended.certificate_fingerprint = context.client_id + "_cert";
    
    return extended;
}

uint64_t AdvancedSeedGenerator::hash_extended_context(const ExtendedSeedContext& context) {
    std::stringstream ss;
    ss << context.client_id << context.connection_id << context.domain_hint 
       << context.geographic_region << context.load_factor;
    
    return std::hash<std::string>{}(ss.str());
}

std::string AdvancedSeedGenerator::get_time_window_key(const std::chrono::system_clock::time_point& time) {
    auto time_t = std::chrono::system_clock::to_time_t(time);
    auto window_start = (time_t / (time_window_duration_.count() * 60)) * (time_window_duration_.count() * 60);
    
    std::stringstream ss;
    ss << "window_" << window_start;
    return ss.str();
}

bool AdvancedSeedGenerator::should_rotate() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::hours>(now - last_rotation_);
    return elapsed.count() >= 24;
}

IPv6PoolManager::IPv6PoolManager(const std::string& ipv6_prefix, size_t pool_size) 
    : prefix_(ipv6_prefix), pool_size_(pool_size) {
}

domain::IPv6Address IPv6PoolManager::allocate(domain::SeedValue seed) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    cleanup_expired_allocations();
    
    auto address = seed_to_address(seed);
    auto address_str = address_to_string(address);
    
    if (allocated_addresses_[address_str]) {
        uint32_t offset = 1;
        do {
            auto modified_seed = seed + offset;
            address = seed_to_address(modified_seed);
            address_str = address_to_string(address);
            offset++;
        } while (allocated_addresses_[address_str] && offset < 1000);
        
        if (offset >= 1000) {
            throw std::runtime_error("unable to allocate unique ipv6 address");
        }
    }
    
    allocated_addresses_[address_str] = true;
    allocation_times_[address_str] = std::chrono::system_clock::now();
    
    return address;
}

void IPv6PoolManager::release(const domain::IPv6Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto address_str = address_to_string(address);
    allocated_addresses_[address_str] = false;
    allocation_times_.erase(address_str);
}

bool IPv6PoolManager::is_available(const domain::IPv6Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto address_str = address_to_string(address);
    return !allocated_addresses_[address_str] && is_in_pool_range(address);
}

std::vector<domain::IPv6Address> IPv6PoolManager::get_active_addresses() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<domain::IPv6Address> active;
    for (const auto& [addr_str, is_allocated] : allocated_addresses_) {
        if (is_allocated) {
            domain::IPv6Address addr = string_to_address(addr_str);
            active.push_back(addr);
        }
    }
    
    return active;
}

bool IPv6PoolManager::expand_pool() {
    expand_pool(1000);
    return true;
}

size_t IPv6PoolManager::get_pool_size() const {
    return get_total_pool_size();
}

void IPv6PoolManager::expand_pool(size_t additional_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    pool_size_ += additional_size;
}

void IPv6PoolManager::compact_pool() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = allocated_addresses_.begin();
    while (it != allocated_addresses_.end()) {
        if (!it->second) {
            allocation_times_.erase(it->first);
            it = allocated_addresses_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t IPv6PoolManager::get_pool_utilization() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t used = 0;
    for (const auto& [addr, is_allocated] : allocated_addresses_) {
        if (is_allocated) used++;
    }
    
    return (used * 100) / pool_size_;
}

size_t IPv6PoolManager::get_total_pool_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pool_size_;
}

domain::IPv6Address IPv6PoolManager::seed_to_address(domain::SeedValue seed) {
    domain::IPv6Address addr{};
    
    auto prefix_part = prefix_.substr(0, prefix_.find('/'));
    auto seed_part = seed & 0xFFFFFFFFFFFF;
    
    for (int i = 0; i < 8; i++) {
        addr[i] = 0xFD;
    }
    
    for (int i = 0; i < 6; i++) {
        addr[10 + i] = (seed_part >> (8 * (5 - i))) & 0xFF;
    }
    
    return addr;
}

std::string IPv6PoolManager::address_to_string(const domain::IPv6Address& address) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << static_cast<int>(address[i])
           << std::setw(2) << static_cast<int>(address[i + 1]);
    }
    
    return ss.str();
}

domain::IPv6Address IPv6PoolManager::string_to_address(const std::string& addr_str) {
    domain::IPv6Address addr{};
    std::stringstream ss(addr_str);
    std::string part;
    int idx = 0;
    
    while (std::getline(ss, part, ':') && idx < 8) {
        if (!part.empty()) {
            uint16_t value = static_cast<uint16_t>(std::stoul(part, nullptr, 16));
            addr[idx * 2] = (value >> 8) & 0xFF;
            addr[idx * 2 + 1] = value & 0xFF;
        }
        idx++;
    }
    
    return addr;
}

bool IPv6PoolManager::is_valid_address(const domain::IPv6Address& address) {
    for (int i = 0; i < 8; i++) {
        if (address[i] != 0xFD) {
            return false;
        }
    }
    return true;
}

bool IPv6PoolManager::is_in_pool_range(const domain::IPv6Address& address) {
    return is_valid_address(address);
}

void IPv6PoolManager::cleanup_expired_allocations() {
    auto now = std::chrono::system_clock::now();
    auto expiry_time = std::chrono::hours(24);
    
    auto it = allocation_times_.begin();
    while (it != allocation_times_.end()) {
        if (now - it->second > expiry_time) {
            allocated_addresses_[it->first] = false;
            it = allocation_times_.erase(it);
        } else {
            ++it;
        }
    }
}

}
