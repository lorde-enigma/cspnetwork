#pragma once

#include "../domain/types.h"
#include "../domain/entities.h"
#include "../domain/interfaces.h"
#include <future>
#include <string>
#include <memory>

namespace seeded_vpn::application {

struct ConnectionRequest {
    std::string client_id;
    std::string authentication_token;
};

struct ConnectionResponse {
    bool success;
    domain::ConnectionId connection_id;
    domain::IPv6Address allocated_address;
    std::string error_message;
};

struct DisconnectionRequest {
    domain::ConnectionId connection_id;
};

struct AddressAllocationRequest {
    domain::ConnectionId connection_id;
    std::string target_domain;
};

struct AddressAllocationResponse {
    bool success;
    domain::IPv6Address address;
    std::string error_message;
};

class IConnectionUseCase {
public:
    virtual ~IConnectionUseCase() = default;
    virtual std::future<ConnectionResponse> execute(const ConnectionRequest& request) = 0;
    virtual std::future<ConnectionResponse> establish_connection(const ConnectionRequest& request) = 0;
    virtual std::future<bool> disconnect(const DisconnectionRequest& request) = 0;
};

class IAuthenticationUseCase {
public:
    virtual ~IAuthenticationUseCase() = default;
    virtual std::future<bool> authenticate(const std::string& client_id, const std::vector<uint8_t>& credentials) = 0;
    virtual std::future<bool> authenticate_client(const std::string& client_id, const std::string& token) = 0;
    virtual std::future<bool> validate_session(domain::ConnectionId connection_id) = 0;
};

class IAddressAllocationUseCase {
public:
    virtual ~IAddressAllocationUseCase() = default;
    virtual std::future<AddressAllocationResponse> execute(const AddressAllocationRequest& request) = 0;
    virtual std::future<AddressAllocationResponse> allocate_seeded_address(const AddressAllocationRequest& request) = 0;
    virtual std::future<bool> release_address(domain::ConnectionId connection_id) = 0;
};

class CreateConnectionUseCase {
private:
    std::shared_ptr<domain::ConnectionManager> connection_manager_;
    std::shared_ptr<domain::SecurityValidator> security_validator_;
    std::shared_ptr<domain::ILogger> logger_;

public:
    CreateConnectionUseCase(
        std::shared_ptr<domain::ConnectionManager> connection_manager,
        std::shared_ptr<domain::SecurityValidator> security_validator,
        std::shared_ptr<domain::ILogger> logger
    );
    
    std::future<ConnectionResponse> execute(const ConnectionRequest& request);
    
private:
    bool validate_client_id(const domain::ClientId& client_id);
    bool authenticate_client(const std::string& client_id, const std::string& token);
};

class EstablishConnectionUseCase {
private:
    std::shared_ptr<domain::ConnectionManager> connection_manager_;
    std::shared_ptr<domain::AddressPoolManager> pool_manager_;
    std::shared_ptr<domain::ILogger> logger_;

public:
    EstablishConnectionUseCase(
        std::shared_ptr<domain::ConnectionManager> connection_manager,
        std::shared_ptr<domain::AddressPoolManager> pool_manager,
        std::shared_ptr<domain::ILogger> logger
    );
    
    std::future<bool> execute(domain::ConnectionId connection_id);
    
private:
    void configure_connection_routing(domain::ConnectionId connection_id);
};

class AllocateIPv6AddressUseCase {
private:
    std::shared_ptr<domain::SeedManager> seed_manager_;
    std::shared_ptr<domain::AddressPoolManager> pool_manager_;
    std::shared_ptr<domain::IConnectionRepository> connection_repository_;
    std::shared_ptr<domain::ILogger> logger_;

public:
    AllocateIPv6AddressUseCase(
        std::shared_ptr<domain::SeedManager> seed_manager,
        std::shared_ptr<domain::AddressPoolManager> pool_manager,
        std::shared_ptr<domain::IConnectionRepository> connection_repository,
        std::shared_ptr<domain::ILogger> logger
    );
    
    std::future<AddressAllocationResponse> execute(const AddressAllocationRequest& request);
    
private:
    domain::SeedData build_seed_context(const AddressAllocationRequest& request);
    bool validate_allocated_address(const domain::IPv6Address& address);
};

class CloseConnectionUseCase {
private:
    std::shared_ptr<domain::ConnectionManager> connection_manager_;
    std::shared_ptr<domain::AddressPoolManager> pool_manager_;
    std::shared_ptr<domain::ILogger> logger_;

public:
    CloseConnectionUseCase(
        std::shared_ptr<domain::ConnectionManager> connection_manager,
        std::shared_ptr<domain::AddressPoolManager> pool_manager,
        std::shared_ptr<domain::ILogger> logger
    );
    
    std::future<bool> execute(const DisconnectionRequest& request);
    
private:
    void cleanup_connection_resources(domain::ConnectionId connection_id);
};

class RotateSeedsUseCase {
private:
    std::shared_ptr<domain::SeedManager> seed_manager_;
    std::shared_ptr<domain::ConnectionManager> connection_manager_;
    std::shared_ptr<domain::ILogger> logger_;

public:
    RotateSeedsUseCase(
        std::shared_ptr<domain::SeedManager> seed_manager,
        std::shared_ptr<domain::ConnectionManager> connection_manager,
        std::shared_ptr<domain::ILogger> logger
    );
    
    std::future<bool> execute();
    
private:
    void handle_active_connections_during_rotation();
    bool verify_rotation_success();
};

class MonitorSystemHealthUseCase {
private:
    std::shared_ptr<domain::ConnectionManager> connection_manager_;
    std::shared_ptr<domain::AddressPoolManager> pool_manager_;
    std::shared_ptr<domain::INetworkInterface> network_interface_;
    std::shared_ptr<domain::ILogger> logger_;

public:
    MonitorSystemHealthUseCase(
        std::shared_ptr<domain::ConnectionManager> connection_manager,
        std::shared_ptr<domain::AddressPoolManager> pool_manager,
        std::shared_ptr<domain::INetworkInterface> network_interface,
        std::shared_ptr<domain::ILogger> logger
    );
    
    struct HealthReport {
        size_t active_connections;
        size_t available_addresses;
        bool network_interface_up;
        std::chrono::milliseconds response_time;
        bool overall_healthy;
    };
    
    std::future<HealthReport> execute();
    
private:
    bool check_network_health();
    bool check_address_pool_health();
    bool check_connection_health();
};

class CleanupExpiredConnectionsUseCase {
private:
    std::shared_ptr<domain::ConnectionManager> connection_manager_;
    std::shared_ptr<domain::IConfigurationProvider> config_provider_;
    std::shared_ptr<domain::ILogger> logger_;

public:
    CleanupExpiredConnectionsUseCase(
        std::shared_ptr<domain::ConnectionManager> connection_manager,
        std::shared_ptr<domain::IConfigurationProvider> config_provider,
        std::shared_ptr<domain::ILogger> logger
    );
    
    std::future<size_t> execute();
    
private:
    std::chrono::seconds get_connection_timeout();
};

}
