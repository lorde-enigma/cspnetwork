#include "../include/infrastructure/connection_seeder.h"
#include <openssl/sha.h>
#include <chrono>
#include <random>
#include <thread>
#include <fstream>
#include <cstring>

namespace seeded_vpn::infrastructure {

const std::vector<std::string> ConnectionSeeder::SERVER_PROFILES = {
    "openvpn-2.6.0",
    "openvpn-2.5.8", 
    "strongswan-5.9.8",
    "wireguard-1.0.20220627",
    "ipsec-tools-0.8.2",
    "tinc-1.0.36",
    "softether-4.38",
    "zerotier-1.10.6"
};

ConnectionSeeder::ConnectionSeeder(domain::SeedValue seed) : seed_(seed) {
}

domain::IPv6Address ConnectionSeeder::generateIPv6Address(const std::string& domain) const {
    std::string context = "ipv6_gen:" + domain;
    auto hash = generateHash(context);
    
    domain::IPv6Address address{};
    std::memcpy(address.data(), hash.data(), 16);
    
    address[0] = 0xfd;
    address[1] = 0x00;
    
    return address;
}

domain::IPv6Address ConnectionSeeder::generateIPv6AddressWithCustomSeed(const std::string& domain, domain::SeedValue customSeed) const {
    std::string context = "ipv6_custom:" + domain + ":" + std::to_string(customSeed);
    auto hash = generateHash(context);
    
    domain::IPv6Address address{};
    std::memcpy(address.data(), hash.data(), 16);
    
    address[0] = 0xfd;
    address[1] = 0x00;
    
    return address;
}

ConnectionSeeder::TunnelFingerprint ConnectionSeeder::generateTunnelFingerprint() const {
    TunnelFingerprint fp;
    
    fp.mtu = generateUint32(1200, 1500, "mtu");
    fp.ttl = generateUint32(32, 255, "ttl");
    fp.compression = generateBool(0.3, "compression");
    fp.fragmentSize = generateUint32(576, 1024, "fragment");
    fp.cipherSuite = generateBytes(4, "cipher");
    fp.keepAliveInterval = generateUint32(10, 60, "keepalive");
    fp.fastReconnect = generateBool(0.7, "fastreconnect");
    fp.stealthMode = generateBool(0.2, "stealth");
    
    return fp;
}

std::string ConnectionSeeder::generateConnectionId() const {
    auto bytes = generateBytes(16, "conn_id");
    
    std::string result;
    result.reserve(32);
    
    for (uint8_t byte : bytes) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", byte);
        result += hex;
    }
    
    return result;
}

uint32_t ConnectionSeeder::generateTiming(uint32_t minMs, uint32_t maxMs) const {
    return generateUint32(minMs, maxMs, "timing");
}

std::vector<uint8_t> ConnectionSeeder::generateSessionKey(uint8_t length) const {
    return generateBytes(length, "session_key");
}

std::string ConnectionSeeder::generateServerProfile() const {
    uint32_t index = generateUint32(0, SERVER_PROFILES.size() - 1, "server_profile");
    return SERVER_PROFILES[index];
}

uint32_t ConnectionSeeder::generateUint32(uint32_t min, uint32_t max, const std::string& context) const {
    if (min > max) {
        std::swap(min, max);
    }
    
    auto hash = generateHash("uint32:" + context);
    uint32_t value = hashToUint32(hash);
    
    if (min == max) {
        return min;
    }
    
    uint64_t range = static_cast<uint64_t>(max) - static_cast<uint64_t>(min) + 1;
    return min + (value % range);
}

std::vector<uint8_t> ConnectionSeeder::generateBytes(size_t size, const std::string& context) const {
    auto hash = generateHash("bytes:" + context);
    
    std::vector<uint8_t> result;
    result.reserve(size);
    
    size_t hashBytes = 0;
    uint32_t counter = 0;
    
    while (result.size() < size) {
        if (hashBytes >= 32) {
            hash = generateHash("bytes:" + context + ":" + std::to_string(counter++));
            hashBytes = 0;
        }
        
        size_t copySize = std::min(size - result.size(), 32 - hashBytes);
        result.insert(result.end(), hash.begin() + hashBytes, hash.begin() + hashBytes + copySize);
        hashBytes += copySize;
    }
    
    return result;
}

bool ConnectionSeeder::generateBool(double probability, const std::string& context) const {
    uint32_t value = generateUint32(0, UINT32_MAX - 1, "bool:" + context);
    double normalized = static_cast<double>(value) / (UINT32_MAX - 1);
    return normalized < probability;
}

std::array<uint8_t, 32> ConnectionSeeder::generateHash(const std::string& context) const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    
    auto it = hashCache_.find(context);
    if (it != hashCache_.end()) {
        cacheHits_++;
        return it->second;
    }
    
    cacheMisses_++;
    
    std::string input = std::to_string(seed_) + ":" + context;
    
    std::array<uint8_t, 32> hash{};
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash.data());
    
    if (hashCache_.size() < MAX_CACHE_SIZE) {
        hashCache_[context] = hash;
    }
    
    return hash;
}

uint32_t ConnectionSeeder::hashToUint32(const std::array<uint8_t, 32>& hash, size_t offset) const {
    uint32_t result = 0;
    std::memcpy(&result, hash.data() + offset, sizeof(uint32_t));
    return result;
}

uint64_t ConnectionSeeder::hashToUint64(const std::array<uint8_t, 32>& hash, size_t offset) const {
    uint64_t result = 0;
    std::memcpy(&result, hash.data() + offset, sizeof(uint64_t));
    return result;
}

void ConnectionSeeder::clearCache() {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    hashCache_.clear();
    cacheHits_ = 0;
    cacheMisses_ = 0;
}

std::pair<size_t, size_t> ConnectionSeeder::getCacheStats() const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    return {cacheHits_, cacheMisses_};
}

SeededRandom::SeededRandom(std::shared_ptr<ConnectionSeeder> seeder, std::string context)
    : seeder_(seeder), context_(std::move(context)) {
}

SeededRandom::result_type SeededRandom::operator()() {
    std::string fullContext = context_ + ":" + std::to_string(callCounter_++);
    return seeder_->generateUint32(0, UINT32_MAX, fullContext);
}

EntropyPool& EntropyPool::getInstance() {
    static EntropyPool instance;
    return instance;
}

EntropyPool::EntropyPool() {
    initializeGenerators();
}

void EntropyPool::initializeGenerators() {
    std::random_device rd;
    auto now = std::chrono::high_resolution_clock::now();
    auto time_seed = static_cast<uint64_t>(now.time_since_epoch().count());
    
    for (size_t i = 0; i < generators_.size(); ++i) {
        uint64_t seed = rd() ^ time_seed ^ (i * 0x9e3779b97f4a7c15ULL);
        generators_[i].seed(seed);
    }
}

std::mt19937 EntropyPool::createUniqueGenerator() {
    collectSystemEntropy();
    
    size_t index = currentGenerator_.fetch_add(1) % generators_.size();
    std::lock_guard<std::mutex> lock(generatorMutexes_[index]);
    
    std::mt19937 generator = generators_[index];
    generators_[index].discard(100 + (generator() % 1000));
    
    return generator;
}

uint32_t EntropyPool::getRandomUint32() {
    size_t index = currentGenerator_.fetch_add(1) % generators_.size();
    std::lock_guard<std::mutex> lock(generatorMutexes_[index]);
    
    totalGenerations_++;
    return generators_[index]();
}

uint64_t EntropyPool::getRandomUint64() {
    uint64_t high = getRandomUint32();
    uint64_t low = getRandomUint32();
    return (high << 32) | low;
}

void EntropyPool::collectEntropy() {
    collectSystemEntropy();
    
    if (totalGenerations_ % 10000 == 0) {
        reseedGenerators();
    }
}

domain::SeedValue EntropyPool::generateHighQualitySeed() {
    collectEntropy();
    return getRandomUint64() ^ getHighResolutionSeed();
}

void EntropyPool::collectSystemEntropy() {
    auto time_entropy = getHighResolutionSeed();
    std::this_thread::sleep_for(std::chrono::nanoseconds(time_entropy % 1000));
}

uint64_t EntropyPool::getHighResolutionSeed() {
    auto now = std::chrono::high_resolution_clock::now();
    return static_cast<uint64_t>(now.time_since_epoch().count());
}

void EntropyPool::reseedGenerators() {
    std::lock_guard<std::mutex> lock(reseedMutex_);
    
    std::random_device rd;
    auto time_seed = getHighResolutionSeed();
    
    for (size_t i = 0; i < generators_.size(); ++i) {
        std::lock_guard<std::mutex> genLock(generatorMutexes_[i]);
        uint64_t seed = rd() ^ time_seed ^ (i * 0x9e3779b97f4a7c15ULL);
        generators_[i].seed(seed);
    }
}

double EntropyPool::getEntropyQuality() {
    double generationRate = static_cast<double>(totalGenerations_.load());
    return std::min(1.0, generationRate / 100000.0);
}

}
