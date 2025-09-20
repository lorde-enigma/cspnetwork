#pragma once

#include "../domain/types.h"
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <array>
#include <random>

namespace seeded_vpn::infrastructure {

class ConnectionSeeder {
public:
    explicit ConnectionSeeder(domain::SeedValue seed);
    
    ~ConnectionSeeder() = default;
    
    ConnectionSeeder(const ConnectionSeeder&) = delete;
    ConnectionSeeder& operator=(const ConnectionSeeder&) = delete;
    ConnectionSeeder(ConnectionSeeder&&) = default;
    ConnectionSeeder& operator=(ConnectionSeeder&&) = default;
    
    domain::IPv6Address generateIPv6Address(const std::string& domain = "") const;
    domain::IPv6Address generateIPv6AddressWithCustomSeed(const std::string& domain, domain::SeedValue customSeed) const;
    
    struct TunnelFingerprint {
        uint16_t mtu;
        uint8_t ttl;
        bool compression;
        uint16_t fragmentSize;
        std::vector<uint8_t> cipherSuite;
        uint8_t keepAliveInterval;
        bool fastReconnect;
        bool stealthMode;
    };
    TunnelFingerprint generateTunnelFingerprint() const;
    
    std::string generateConnectionId() const;
    
    uint32_t generateTiming(uint32_t minMs, uint32_t maxMs) const;
    
    std::vector<uint8_t> generateSessionKey(uint8_t length = 32) const;
    
    std::string generateServerProfile() const;
    
    uint32_t generateUint32(uint32_t min, uint32_t max, const std::string& context = "") const;
    
    std::vector<uint8_t> generateBytes(size_t size, const std::string& context = "") const;
    
    bool generateBool(double probability = 0.5, const std::string& context = "") const;
    
    domain::SeedValue getSeed() const noexcept { return seed_; }
    
    void clearCache();
    
    std::pair<size_t, size_t> getCacheStats() const;

private:
    std::array<uint8_t, 32> generateHash(const std::string& context) const;
    
    uint32_t hashToUint32(const std::array<uint8_t, 32>& hash, size_t offset = 0) const;
    
    uint64_t hashToUint64(const std::array<uint8_t, 32>& hash, size_t offset = 0) const;
    
    domain::SeedValue seed_;
    
    mutable std::mutex cacheMutex_;
    mutable std::unordered_map<std::string, std::array<uint8_t, 32>> hashCache_;
    mutable size_t cacheHits_ = 0;
    mutable size_t cacheMisses_ = 0;
    
    static constexpr size_t MAX_CACHE_SIZE = 1000;
    
    static const std::vector<std::string> SERVER_PROFILES;
};

class SeededRandom {
public:
    using result_type = uint32_t;
    
    explicit SeededRandom(std::shared_ptr<ConnectionSeeder> seeder, std::string context = "");
    
    result_type operator()();
    
    static constexpr result_type min() { return 0; }
    
    static constexpr result_type max() { return UINT32_MAX; }
    
    void seed(result_type) {}

private:
    std::shared_ptr<ConnectionSeeder> seeder_;
    std::string context_;
    mutable uint32_t callCounter_ = 0;
};

class EntropyPool {
public:
    static EntropyPool& getInstance();
    
    std::mt19937 createUniqueGenerator();
    uint32_t getRandomUint32();
    uint64_t getRandomUint64();
    void collectEntropy();
    double getEntropyQuality();
    
    domain::SeedValue generateHighQualitySeed();

private:
    EntropyPool();
    
    std::array<std::mt19937, 16> generators_;
    std::array<std::mutex, 16> generatorMutexes_;
    std::atomic<size_t> currentGenerator_{0};
    std::atomic<uint64_t> totalGenerations_{0};
    mutable std::mutex reseedMutex_;
    
    void initializeGenerators();
    void reseedGenerators();
    void collectSystemEntropy();
    uint64_t getHighResolutionSeed();
};

}
