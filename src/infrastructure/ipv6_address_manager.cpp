#include "../include/infrastructure/ipv6_address_manager.h"
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <openssl/evp.h>

namespace seeded_vpn::infrastructure {

IPv6AddressManager& IPv6AddressManager::getInstance() {
    static IPv6AddressManager instance;
    return instance;
}

IPv6AddressManager::IPv6AddressManager() 
    : defaultInterface_("csp0")
    , addressPrefix_(DEFAULT_PREFIX)
    , maxPoolSize_(DEFAULT_POOL_SIZE) {
}

IPv6AddressManager::~IPv6AddressManager() {
    clearCache();
}

domain::IPv6Address IPv6AddressManager::allocate(domain::SeedValue seed) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    domain::IPv6Address address = seedToAddress(seed);
    
    if (!is_available(address)) {
        return {};
    }
    
    if (addSystemAddress(defaultInterface_, address)) {
        addToCache(defaultInterface_, address, seed);
        totalAllocations_++;
        return address;
    }
    
    return {};
}

void IPv6AddressManager::release(const domain::IPv6Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    removeSystemAddress(defaultInterface_, address);
    removeFromCache(defaultInterface_, address);
    totalReleases_++;
}

bool IPv6AddressManager::is_available(const domain::IPv6Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (isCached(defaultInterface_, address)) {
        cacheHits_++;
        return false;
    }
    
    cacheMisses_++;
    return !checkAddressExists(defaultInterface_, address);
}

std::vector<domain::IPv6Address> IPv6AddressManager::get_active_addresses() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<domain::IPv6Address> addresses;
    addresses.reserve(addressCache_.size());
    
    for (const auto& [key, info] : addressCache_) {
        if (info.is_active) {
            addresses.push_back(info.address);
        }
    }
    
    return addresses;
}

bool IPv6AddressManager::expand_pool() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (addressCache_.size() >= maxPoolSize_) {
        return false;
    }
    
    maxPoolSize_ += 1000;
    return true;
}

size_t IPv6AddressManager::get_pool_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return maxPoolSize_;
}

IPv6AddressManager::Result IPv6AddressManager::allocateAddressToInterface(const std::string& interface, domain::SeedValue seed) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!isValidInterface(interface)) {
        return Result::INTERFACE_NOT_FOUND;
    }
    
    domain::IPv6Address address = seedToAddress(seed);
    
    if (checkAddressExists(interface, address)) {
        return Result::ALREADY_EXISTS;
    }
    
    if (addressCache_.size() >= maxPoolSize_) {
        return Result::POOL_EXHAUSTED;
    }
    
    if (addSystemAddress(interface, address)) {
        addToCache(interface, address, seed);
        totalAllocations_++;
        return Result::SUCCESS;
    }
    
    return Result::SYSTEM_ERROR;
}

bool IPv6AddressManager::checkAddressExists(const std::string& interface, const domain::IPv6Address& address) {
    if (isCached(interface, address)) {
        return true;
    }
    
    std::string addrStr = addressToString(address);
    std::string command = "ip -6 addr show " + interface + " | grep " + addrStr;
    
    return executeCommand(command);
}

domain::IPv6Address IPv6AddressManager::seedToAddress(domain::SeedValue seed) const {
    std::string domain = addressPrefix_.empty() ? DEFAULT_PREFIX : addressPrefix_;
    std::string input = std::to_string(seed) + ":ipv6:" + domain;
    
    std::array<uint8_t, 32> hash;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.c_str(), input.length());
    unsigned int hashLen;
    EVP_DigestFinal_ex(ctx, hash.data(), &hashLen);
    EVP_MD_CTX_free(ctx);
    
    domain::IPv6Address addr;
    addr[0] = 0x2a;
    addr[1] = 0x0e;
    addr[2] = 0xb1;
    addr[3] = 0x07;
    addr[4] = 0x1e;
    addr[5] = 0xf0;
    
    for (int i = 6; i < 16; i++) {
        addr[i] = hash[i - 6];
    }
    
    return addr;
}

std::string IPv6AddressManager::addressToString(const domain::IPv6Address& address) const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < address.size(); i += 2) {
        if (i > 0) oss << ":";
        oss << std::setw(2) << static_cast<int>(address[i])
            << std::setw(2) << static_cast<int>(address[i + 1]);
    }
    
    return oss.str();
}

bool IPv6AddressManager::addSystemAddress(const std::string& interface, const domain::IPv6Address& address) {
    std::string addrStr = addressToString(address);
    std::string command = "ip -6 addr add " + addrStr + "/128 dev " + interface + " 2>/dev/null";
    
    return executeCommand(command);
}

bool IPv6AddressManager::removeSystemAddress(const std::string& interface, const domain::IPv6Address& address) {
    std::string addrStr = addressToString(address);
    std::string command = "ip -6 addr del " + addrStr + "/128 dev " + interface + " 2>/dev/null";
    
    return executeCommand(command);
}

void IPv6AddressManager::addToCache(const std::string& interface, const domain::IPv6Address& address, domain::SeedValue seed) {
    std::string key = getCacheKey(interface, address);
    
    AddressInfo info;
    info.address = address;
    info.seed = seed;
    info.allocated_at = std::chrono::steady_clock::now();
    info.interface_name = interface;
    info.is_active = true;
    
    addressCache_[key] = info;
    
    if (addressCache_.size() > MAX_CACHE_SIZE) {
        cleanupExpired(std::chrono::minutes{30});
    }
}

bool IPv6AddressManager::isCached(const std::string& interface, const domain::IPv6Address& address) const {
    std::string key = getCacheKey(interface, address);
    auto it = addressCache_.find(key);
    return it != addressCache_.end() && it->second.is_active;
}

void IPv6AddressManager::removeFromCache(const std::string& interface, const domain::IPv6Address& address) {
    std::string key = getCacheKey(interface, address);
    auto it = addressCache_.find(key);
    if (it != addressCache_.end()) {
        it->second.is_active = false;
        addressCache_.erase(it);
    }
}

bool IPv6AddressManager::isValidInterface(const std::string& interface) const {
    std::string command = "ip link show " + interface + " 2>/dev/null";
    return executeCommand(command);
}

std::string IPv6AddressManager::getCacheKey(const std::string& interface, const domain::IPv6Address& address) const {
    return interface + ":" + addressToString(address);
}

bool IPv6AddressManager::executeCommand(const std::string& command) const {
    int result = std::system(command.c_str());
    return WEXITSTATUS(result) == 0;
}

void IPv6AddressManager::clearCache() {
    std::lock_guard<std::mutex> lock(mutex_);
    addressCache_.clear();
}

size_t IPv6AddressManager::getCacheSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return addressCache_.size();
}

void IPv6AddressManager::cleanupExpired(std::chrono::minutes max_age) {
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - max_age;
    
    auto it = addressCache_.begin();
    while (it != addressCache_.end()) {
        if (it->second.allocated_at < cutoff) {
            removeSystemAddress(it->second.interface_name, it->second.address);
            it = addressCache_.erase(it);
        } else {
            ++it;
        }
    }
}

std::pair<size_t, size_t> IPv6AddressManager::getStatistics() const {
    return {totalAllocations_.load(), totalReleases_.load()};
}

void IPv6AddressManager::setAddressPrefix(const std::string& prefix) {
    std::lock_guard<std::mutex> lock(mutex_);
    addressPrefix_ = prefix;
}

SeededIPv6Manager::SeededIPv6Manager(std::shared_ptr<domain::ISeedGenerator> seedGenerator,
                                     std::shared_ptr<IPv6AddressManager> addressManager)
    : seedGenerator_(seedGenerator), addressManager_(addressManager) {
}

SeededIPv6Manager::AllocationResult SeededIPv6Manager::allocateForClient(const domain::SeedContext& context, const std::string& interface) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string clientKey = getClientKey(context);
    
    if (clientAllocations_.find(clientKey) != clientAllocations_.end()) {
        AllocationResult result;
        result.result = IPv6AddressManager::Result::ALREADY_EXISTS;
        result.address = clientAllocations_[clientKey];
        result.seed = clientSeeds_[clientKey];
        return result;
    }
    
    domain::SeedValue seed = seedGenerator_->generate(context);
    std::string targetInterface = interface.empty() ? "csp0" : interface;
    
    IPv6AddressManager::Result allocResult = addressManager_->allocateAddressToInterface(targetInterface, seed);
    
    AllocationResult result;
    result.result = allocResult;
    result.seed = seed;
    
    if (allocResult == IPv6AddressManager::Result::SUCCESS) {
        result.address = addressManager_->seedToAddress(seed);
        clientAllocations_[clientKey] = result.address;
        clientSeeds_[clientKey] = seed;
    }
    
    return result;
}

std::string SeededIPv6Manager::getClientKey(const domain::SeedContext& context) const {
    return context.client_id + ":" + std::to_string(context.connection_id);
}

}
