#pragma once

#include "types.h"
#include "interfaces.h"
#include <memory>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <chrono>
#include <shared_mutex>
#include <atomic>
#include <optional>

namespace seeded_vpn::domain {

class VPNConnection {
public:
    VPNConnection(ConnectionId id, const ClientId& client_id, const IPv6Address& assigned_address);
    
    void update_state(ConnectionState new_state);
    void record_activity();
    void update_statistics(uint64_t bytes_sent, uint64_t bytes_received, 
                          uint32_t packets_sent, uint32_t packets_received);
    
    bool is_active() const;
    bool is_expired(std::chrono::seconds timeout) const;
    ConnectionContext get_context() const;
    
    void set_encryption_key(const std::vector<uint8_t>& key);

private:
    void validate_state_transition(ConnectionState from, ConnectionState to) const;
    
    ConnectionContext context_;
    std::chrono::steady_clock::time_point last_activity_timestamp_;
    uint64_t bytes_transferred_;
    uint32_t packets_transferred_;
    double connection_quality_;
    bool encryption_enabled_;
    std::vector<uint8_t> encryption_key_;
};

struct SeedUsage {
    ClientId client_id;
    std::chrono::steady_clock::time_point created_at;
    std::optional<std::chrono::steady_clock::time_point> invalidated_at;
    bool is_active;
};

class SeedManager {
public:
    SeedManager(std::shared_ptr<ISeedGenerator> generator);
    
    SeedValue generate_seed_for_client(const ClientId& client_id, ConnectionId connection_id);
    void rotate_seeds_if_needed();
    void set_rotation_interval(std::chrono::seconds interval);
    std::vector<SeedValue> get_active_seeds() const;
    void invalidate_seed(SeedValue seed);
    
private:
    void track_seed_usage(SeedValue seed, const ClientId& client_id);
    void cleanup_seed_history();
    
    std::shared_ptr<ISeedGenerator> seed_generator_;
    mutable std::shared_mutex seed_mutex_;
    std::chrono::steady_clock::time_point last_rotation_;
    std::chrono::seconds rotation_interval_;
    size_t seed_history_limit_;
    std::unordered_map<SeedValue, SeedUsage> seed_usage_history_;
};

class ConnectionManager {
public:
    ConnectionManager(std::shared_ptr<IConnectionRepository> repository,
                     std::shared_ptr<ILogger> logger);
    
    std::unique_ptr<VPNConnection> create_connection(const ClientId& client_id, 
                                                    const IPv6Address& assigned_address);
    std::optional<VPNConnection> get_connection(ConnectionId id);
    void close_connection(ConnectionId id);
    std::vector<VPNConnection> get_client_connections(const ClientId& client_id);
    void cleanup_expired_connections();
    void set_max_connections_per_client(size_t max_connections);
    void set_connection_timeout(std::chrono::seconds timeout);
    
private:
    void validate_client_connection_limit(const ClientId& client_id);
    ConnectionId generate_connection_id();
    
    std::shared_ptr<IConnectionRepository> connection_repository_;
    std::shared_ptr<ILogger> logger_;
    size_t max_connections_per_client_;
    std::chrono::seconds connection_timeout_;
};

struct AllocationInfo {
    SeedValue seed;
    std::chrono::steady_clock::time_point allocated_at;
};

class AddressPoolManager {
public:
    AddressPoolManager(std::shared_ptr<IIPv6AddressManager> address_manager,
                      std::shared_ptr<ILogger> logger);
    
    IPv6Address allocate_address(SeedValue seed);
    void release_address(const IPv6Address& address);
    bool is_address_available(const IPv6Address& address);
    std::vector<IPv6Address> get_allocated_addresses();
    size_t get_pool_utilization() const;
    void set_expansion_threshold(double threshold);
    
private:
    void track_allocation(const IPv6Address& address, SeedValue seed);
    void check_pool_expansion_needed();
    
    std::shared_ptr<IIPv6AddressManager> address_manager_;
    std::shared_ptr<ILogger> logger_;
    mutable std::shared_mutex allocation_mutex_;
    std::unordered_map<IPv6Address, AllocationInfo> allocation_tracking_;
    double pool_expansion_threshold_;
    size_t max_pool_size_;
    std::chrono::seconds allocation_timeout_;
};

struct FailedAttemptInfo {
    size_t attempt_count;
    std::chrono::steady_clock::time_point last_attempt;
};

class SecurityValidator {
public:
    SecurityValidator(std::shared_ptr<ICryptographyService> crypto_service,
                     std::shared_ptr<ILogger> logger);
    
    bool validate_client_identity(const ClientId& client_id, 
                                 const std::vector<uint8_t>& credentials);
    bool validate_connection_integrity(const std::vector<uint8_t>& data,
                                      const std::vector<uint8_t>& signature,
                                      const std::vector<uint8_t>& public_key);
    std::vector<uint8_t> generate_session_key();
    
private:
    bool is_client_locked_out(const ClientId& client_id);
    void record_failed_attempt(const ClientId& client_id);
    void clear_failed_attempts(const ClientId& client_id);
    bool perform_credential_validation(const std::vector<uint8_t>& credentials);
    
    std::shared_ptr<ICryptographyService> crypto_service_;
    std::shared_ptr<ILogger> logger_;
    std::mutex validation_mutex_;
    std::unordered_map<ClientId, FailedAttemptInfo> failed_attempts_;
    size_t max_failed_attempts_;
    std::chrono::minutes lockout_duration_;
};

}
