#pragma once

#include "../domain/types.h"
#include "../domain/interfaces.h"
#include "connection_seeder.h"
#include "ipv6_address_manager.h"
#include <memory>
#include <string>
#include <unordered_map>
#include <mutex>
#include <optional>

namespace seeded_vpn::infrastructure {

class SeededConnectionManager {
public:
    struct ConnectionConfig {
        std::string clientId;
        std::string interfaceName;
        domain::SeedStrategy strategy;
        bool enableStealth;
        uint32_t sessionTimeout;
    };

    struct ActiveConnection {
        domain::ConnectionId connectionId;
        std::string clientId;
        domain::IPv6Address assignedAddress;
        std::shared_ptr<ConnectionSeeder> seeder;
        domain::ConnectionState state;
        std::chrono::steady_clock::time_point createdAt;
        std::chrono::steady_clock::time_point lastActivity;
        ConnectionSeeder::TunnelFingerprint fingerprint;
    };

    explicit SeededConnectionManager(std::shared_ptr<domain::ISeedGenerator> seedGenerator);
    
    domain::ConnectionId establishConnection(const ConnectionConfig& config);
    void terminateConnection(domain::ConnectionId connectionId);
    bool updateConnectionActivity(domain::ConnectionId connectionId);
    
    std::shared_ptr<ConnectionSeeder> getConnectionSeeder(domain::ConnectionId connectionId);
    std::optional<ActiveConnection> getConnection(domain::ConnectionId connectionId);
    std::vector<ActiveConnection> getActiveConnections();
    std::vector<ActiveConnection> getClientConnections(const std::string& clientId);
    
    void cleanupIdleConnections(std::chrono::minutes maxIdle = std::chrono::minutes{30});
    void setDefaultInterface(const std::string& interface);
    
    size_t getActiveConnectionCount() const;
    size_t getTotalConnectionCount() const;
    
    struct Statistics {
        size_t totalConnections;
        size_t activeConnections;
        size_t failedConnections;
        size_t addressAllocations;
        double avgConnectionDuration;
    };
    Statistics getStatistics() const;

private:
    std::shared_ptr<domain::ISeedGenerator> seedGenerator_;
    std::shared_ptr<IPv6AddressManager> addressManager_;
    std::shared_ptr<SeededIPv6Manager> seededManager_;
    
    mutable std::mutex mutex_;
    std::unordered_map<domain::ConnectionId, ActiveConnection> connections_;
    std::unordered_map<std::string, std::vector<domain::ConnectionId>> clientConnections_;
    
    std::string defaultInterface_;
    std::atomic<domain::ConnectionId> nextConnectionId_{1};
    std::atomic<size_t> totalConnections_{0};
    std::atomic<size_t> failedConnections_{0};
    
    domain::ConnectionId generateConnectionId();
    domain::SeedValue generateConnectionSeed(const ConnectionConfig& config, domain::ConnectionId connectionId);
    bool allocateAddressForConnection(ActiveConnection& connection);
    void releaseConnectionResources(const ActiveConnection& connection);
    
    static constexpr size_t MAX_CONNECTIONS_PER_CLIENT = 10;
};

class ConnectionFactory {
public:
    static std::shared_ptr<SeededConnectionManager> createConnectionManager();
    static std::shared_ptr<ConnectionSeeder> createConnectionSeeder(domain::SeedValue seed);
    static std::shared_ptr<domain::ISeedGenerator> createAdvancedSeedGenerator();
};

}
