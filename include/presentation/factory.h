#pragma once

#include "domain/entities.h"
#include "application/services.h"
#include "infrastructure/seed_generator.h"
#include "infrastructure/repositories.h"
#include <memory>

namespace seeded_vpn::presentation {

class DependencyFactory {
public:
    static std::shared_ptr<domain::ISeedGenerator> create_seed_generator();
    static std::shared_ptr<domain::IIPv6AddressManager> create_ipv6_manager(const std::string& prefix);
    static std::shared_ptr<domain::IConnectionRepository> create_connection_repository();
    static std::shared_ptr<domain::INetworkInterface> create_network_interface(const std::string& interface_name);
    static std::shared_ptr<domain::ILogger> create_logger();
    
    static std::shared_ptr<domain::SeedManager> create_seed_manager();
    static std::shared_ptr<domain::ConnectionManager> create_connection_manager();
    static std::shared_ptr<domain::AddressPoolManager> create_address_pool_manager();
    static std::shared_ptr<domain::SecurityValidator> create_security_validator();
    
    static std::shared_ptr<application::ConnectionService> create_connection_service();
    static std::shared_ptr<application::IAddressAllocationUseCase> create_address_allocation_use_case();
    static std::shared_ptr<application::IAuthenticationUseCase> create_authentication_use_case();

private:
    static std::shared_ptr<domain::ISeedGenerator> seed_generator_;
    static std::shared_ptr<domain::IIPv6AddressManager> ipv6_manager_;
    static std::shared_ptr<domain::IConnectionRepository> connection_repository_;
    static std::shared_ptr<domain::INetworkInterface> network_interface_;
    static std::shared_ptr<domain::ILogger> logger_;
    
    static std::shared_ptr<domain::SeedManager> seed_manager_;
    static std::shared_ptr<domain::ConnectionManager> connection_manager_;
    static std::shared_ptr<domain::AddressPoolManager> address_pool_manager_;
    static std::shared_ptr<domain::SecurityValidator> security_validator_;
    
    static std::shared_ptr<application::IAuthenticationUseCase> auth_use_case_;
};

}
