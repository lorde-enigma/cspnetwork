#pragma once

#include "../domain/types.h"
#include "../domain/interfaces.h"
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <memory>
#include <vector>
#include <chrono>
#include <atomic>

namespace seeded_vpn::infrastructure {

class IPv6AddressManager : public domain::IIPv6AddressManager {
public:
    enum class Result {
        SUCCESS,
        ALREADY_EXISTS,
        SYSTEM_ERROR,
        PERMISSION_ERROR,
        INTERFACE_NOT_FOUND,
        POOL_EXHAUSTED,
        INVALID_SEED
    };

    struct AddressInfo {
        domain::IPv6Address address;
        domain::SeedValue seed;
        std::chrono::steady_clock::time_point allocated_at;
        std::string interface_name;
        bool is_active;
    };

    static IPv6AddressManager& getInstance();
    
    domain::IPv6Address allocate(domain::SeedValue seed) override;
    void release(const domain::IPv6Address& address) override;
    bool is_available(const domain::IPv6Address& address) override;
    std::vector<domain::IPv6Address> get_active_addresses() override;
    bool expand_pool() override;
    size_t get_pool_size() const override;

    Result allocateAddressToInterface(const std::string& interface, domain::SeedValue seed);
    Result allocateSpecificAddress(const std::string& interface, const domain::IPv6Address& address);
    void releaseFromInterface(const std::string& interface, const domain::IPv6Address& address);
    bool checkAddressExists(const std::string& interface, const domain::IPv6Address& address);
    
    std::vector<domain::IPv6Address> listInterfaceAddresses(const std::string& interface);
    void cleanup(const std::string& interface);
    void cleanupExpired(std::chrono::minutes max_age = std::chrono::minutes{60});
    
    size_t getCacheSize() const;
    void clearCache();
    void setDefaultInterface(const std::string& interface);
    void setAddressPrefix(const std::string& prefix);
    
    std::pair<size_t, size_t> getStatistics() const;
    
    domain::IPv6Address seedToAddress(domain::SeedValue seed) const;

private:
    IPv6AddressManager();
    ~IPv6AddressManager();
    IPv6AddressManager(const IPv6AddressManager&) = delete;
    IPv6AddressManager& operator=(const IPv6AddressManager&) = delete;

    std::string addressToString(const domain::IPv6Address& address) const;
    domain::IPv6Address stringToAddress(const std::string& address_str) const;
    std::string getCacheKey(const std::string& interface, const domain::IPv6Address& address) const;
    
    bool executeCommand(const std::string& command) const;
    bool addSystemAddress(const std::string& interface, const domain::IPv6Address& address);
    bool removeSystemAddress(const std::string& interface, const domain::IPv6Address& address);
    bool isValidInterface(const std::string& interface) const;
    
    void addToCache(const std::string& interface, const domain::IPv6Address& address, domain::SeedValue seed);
    bool isCached(const std::string& interface, const domain::IPv6Address& address) const;
    void removeFromCache(const std::string& interface, const domain::IPv6Address& address);
    
    bool isInAddressPool(const domain::IPv6Address& address) const;
    domain::IPv6Address generateFromPrefix(domain::SeedValue seed) const;
    uint64_t hashAddress(const domain::IPv6Address& address) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, AddressInfo> addressCache_;
    std::unordered_set<std::string> systemAddresses_;
    
    std::string defaultInterface_;
    std::string addressPrefix_;
    size_t maxPoolSize_;
    
    std::atomic<size_t> totalAllocations_{0};
    std::atomic<size_t> totalReleases_{0};
    std::atomic<size_t> cacheHits_{0};
    std::atomic<size_t> cacheMisses_{0};
    
    static constexpr size_t DEFAULT_POOL_SIZE = 10000;
    static constexpr char DEFAULT_PREFIX[] = "fd00:1337:beef";
    static constexpr size_t MAX_CACHE_SIZE = 5000;
};

class SeededIPv6Manager {
public:
    explicit SeededIPv6Manager(std::shared_ptr<domain::ISeedGenerator> seedGenerator,
                               std::shared_ptr<IPv6AddressManager> addressManager);
    
    struct AllocationResult {
        IPv6AddressManager::Result result;
        domain::IPv6Address address;
        domain::SeedValue seed;
    };
    
    AllocationResult allocateForClient(const domain::SeedContext& context, const std::string& interface = "");
    void releaseForClient(const domain::SeedContext& context);
    bool isClientAllocated(const domain::SeedContext& context) const;
    
    std::vector<domain::IPv6Address> getClientAddresses(const std::string& clientId) const;
    void cleanupClient(const std::string& clientId);
    
    size_t getActiveAllocations() const;
    void setAllocationStrategy(domain::SeedStrategy strategy);

private:
    std::shared_ptr<domain::ISeedGenerator> seedGenerator_;
    std::shared_ptr<IPv6AddressManager> addressManager_;
    
    mutable std::mutex mutex_;
    std::unordered_map<std::string, domain::IPv6Address> clientAllocations_;
    std::unordered_map<std::string, domain::SeedValue> clientSeeds_;
    
    std::string getClientKey(const domain::SeedContext& context) const;
};

}
