#include "../include/infrastructure/seeded_connection_manager.h"
#include <iostream>
#include <sstream>
#include <algorithm>

namespace seeded_vpn::infrastructure {

SeededConnectionManager::SeededConnectionManager(std::shared_ptr<domain::ISeedGenerator> seedGenerator)
    : seedGenerator_(seedGenerator), 
      addressManager_(std::shared_ptr<IPv6AddressManager>(&IPv6AddressManager::getInstance(), [](IPv6AddressManager*){})),
      seededManager_(std::make_shared<SeededIPv6Manager>(seedGenerator_, addressManager_)) {
}

domain::ConnectionId SeededConnectionManager::establishConnection(const ConnectionConfig& config) {
    domain::ConnectionId connectionId = generateConnectionId();
    domain::SeedValue seed = generateConnectionSeed(config, connectionId);
    
    ActiveConnection connection;
    connection.connectionId = connectionId;
    connection.clientId = config.clientId;
    connection.seeder = std::make_shared<ConnectionSeeder>(seed);
    connection.state = domain::ConnectionState::CONNECTING;
    connection.createdAt = std::chrono::steady_clock::now();
    connection.lastActivity = connection.createdAt;
    connection.fingerprint = connection.seeder->generateTunnelFingerprint();
    
    if (!allocateAddressForConnection(connection)) {
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    connections_[connectionId] = std::move(connection);
    clientConnections_[config.clientId].push_back(connectionId);
    totalConnections_++;
    
    return connectionId;
}

void SeededConnectionManager::terminateConnection(domain::ConnectionId connectionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = connections_.find(connectionId);
    if (it != connections_.end()) {
        releaseConnectionResources(it->second);
        
        auto& clientConnections = clientConnections_[it->second.clientId];
        clientConnections.erase(
            std::remove(clientConnections.begin(), clientConnections.end(), connectionId),
            clientConnections.end()
        );
        
        connections_.erase(it);
    }
}

bool SeededConnectionManager::updateConnectionActivity(domain::ConnectionId connectionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = connections_.find(connectionId);
    if (it != connections_.end()) {
        it->second.lastActivity = std::chrono::steady_clock::now();
        return true;
    }
    return false;
}

std::shared_ptr<ConnectionSeeder> SeededConnectionManager::getConnectionSeeder(domain::ConnectionId connectionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = connections_.find(connectionId);
    return (it != connections_.end()) ? it->second.seeder : nullptr;
}

std::optional<SeededConnectionManager::ActiveConnection> SeededConnectionManager::getConnection(domain::ConnectionId connectionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = connections_.find(connectionId);
    return (it != connections_.end()) ? std::optional<ActiveConnection>{it->second} : std::nullopt;
}

std::vector<SeededConnectionManager::ActiveConnection> SeededConnectionManager::getActiveConnections() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ActiveConnection> result;
    for (const auto& pair : connections_) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<SeededConnectionManager::ActiveConnection> SeededConnectionManager::getClientConnections(const std::string& clientId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ActiveConnection> result;
    auto it = clientConnections_.find(clientId);
    if (it != clientConnections_.end()) {
        for (domain::ConnectionId id : it->second) {
            auto connIt = connections_.find(id);
            if (connIt != connections_.end()) {
                result.push_back(connIt->second);
            }
        }
    }
    return result;
}

void SeededConnectionManager::cleanupIdleConnections(std::chrono::minutes maxIdle) {
    auto now = std::chrono::steady_clock::now();
    std::vector<domain::ConnectionId> toRemove;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& pair : connections_) {
            if (now - pair.second.lastActivity > maxIdle) {
                toRemove.push_back(pair.first);
            }
        }
    }
    
    for (domain::ConnectionId id : toRemove) {
        terminateConnection(id);
    }
}

void SeededConnectionManager::setDefaultInterface(const std::string& interface) {
    defaultInterface_ = interface;
}

size_t SeededConnectionManager::getActiveConnectionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connections_.size();
}

size_t SeededConnectionManager::getTotalConnectionCount() const {
    return totalConnections_.load();
}

SeededConnectionManager::Statistics SeededConnectionManager::getStatistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Statistics stats;
    stats.totalConnections = totalConnections_.load();
    stats.activeConnections = connections_.size();
    stats.failedConnections = failedConnections_.load();
    stats.addressAllocations = stats.totalConnections;
    stats.avgConnectionDuration = 0.0;
    
    if (!connections_.empty()) {
        auto now = std::chrono::steady_clock::now();
        auto totalDuration = std::chrono::duration<double>::zero();
        
        for (const auto& pair : connections_) {
            totalDuration += now - pair.second.createdAt;
        }
        
        stats.avgConnectionDuration = totalDuration.count() / connections_.size();
    }
    
    return stats;
}

domain::ConnectionId SeededConnectionManager::generateConnectionId() {
    return nextConnectionId_.fetch_add(1);
}

domain::SeedValue SeededConnectionManager::generateConnectionSeed(const ConnectionConfig& config, domain::ConnectionId connectionId) {
    domain::SeedContext context;
    context.client_id = config.clientId;
    context.connection_id = connectionId;
    return seedGenerator_->generate(context);
}

bool SeededConnectionManager::allocateAddressForConnection(ActiveConnection& connection) {
    if (seededManager_) {
        domain::SeedContext context;
        context.client_id = connection.clientId;
        context.connection_id = connection.connectionId;
        
        auto result = seededManager_->allocateForClient(context, connection.clientId);
        if (result.result == IPv6AddressManager::Result::SUCCESS) {
            connection.assignedAddress = result.address;
            return true;
        }
    }
    return false;
}

void SeededConnectionManager::releaseConnectionResources(const ActiveConnection& connection) {
    if (addressManager_) {
        addressManager_->release(connection.assignedAddress);
    }
}

}
