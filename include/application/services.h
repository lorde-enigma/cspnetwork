#pragma once

#include "use_cases.h"
#include "../domain/entities.h"
#include "../domain/interfaces.h"
#include <memory>
#include <vector>
#include <optional>

namespace seeded_vpn::application {

struct EstablishConnectionRequest {
    std::string client_id;
    std::vector<uint8_t> credentials;
};

struct ConnectionResult {
    bool success;
    domain::ConnectionId connection_id;
    domain::IPv6Address allocated_address;
    std::string error_message;
};

class ConnectionService {
public:
    ConnectionService(
        std::shared_ptr<domain::ConnectionManager> connection_manager,
        std::shared_ptr<domain::AddressPoolManager> address_pool_manager,
        std::shared_ptr<domain::SeedManager> seed_manager,
        std::shared_ptr<domain::SecurityValidator> security_validator,
        std::shared_ptr<domain::ILogger> logger
    );
    
    ConnectionResult establish_connection(const EstablishConnectionRequest& request);
    bool terminate_connection(domain::ConnectionId connection_id);
    std::vector<domain::ConnectionContext> get_active_connections();
    std::optional<domain::ConnectionContext> get_connection_details(domain::ConnectionId connection_id);
    void set_max_concurrent_connections(size_t max_connections);

private:
    bool validate_connection_limits();
    
    std::shared_ptr<domain::ConnectionManager> connection_manager_;
    std::shared_ptr<domain::AddressPoolManager> address_pool_manager_;
    std::shared_ptr<domain::SeedManager> seed_manager_;
    std::shared_ptr<domain::SecurityValidator> security_validator_;
    std::shared_ptr<domain::ILogger> logger_;
    size_t max_concurrent_connections_;
};

class AddressAllocationUseCase : public IAddressAllocationUseCase {
public:
    AddressAllocationUseCase(
        std::shared_ptr<domain::ConnectionManager> connection_manager,
        std::shared_ptr<domain::AddressPoolManager> pool_manager
    );
    
    std::future<AddressAllocationResponse> execute(const AddressAllocationRequest& request) override;
    std::future<AddressAllocationResponse> allocate_seeded_address(const AddressAllocationRequest& request) override;
    std::future<bool> release_address(domain::ConnectionId connection_id) override;

private:
    std::shared_ptr<domain::ConnectionManager> connection_manager_;
    std::shared_ptr<domain::AddressPoolManager> pool_manager_;
    
    std::string generate_domain_hash(const std::string& domain);
};

class AuthenticationUseCase : public IAuthenticationUseCase {
public:
    std::future<bool> authenticate(const std::string& client_id, const std::vector<uint8_t>& credentials) override;
    std::future<bool> authenticate_client(const std::string& client_id, const std::string& token) override;
    std::future<bool> validate_session(domain::ConnectionId connection_id) override;
};

}
