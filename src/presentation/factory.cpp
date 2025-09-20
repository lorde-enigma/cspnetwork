#include "presentation/factory.h"
#include "application/services.h"
#include "infrastructure/config_manager.h"
#include <filesystem>

namespace seeded_vpn::presentation {

std::shared_ptr<domain::ISeedGenerator> DependencyFactory::seed_generator_ = nullptr;
std::shared_ptr<domain::IIPv6AddressManager> DependencyFactory::ipv6_manager_ = nullptr;
std::shared_ptr<domain::IConnectionRepository> DependencyFactory::connection_repository_ = nullptr;
std::shared_ptr<domain::INetworkInterface> DependencyFactory::network_interface_ = nullptr;
std::shared_ptr<domain::ILogger> DependencyFactory::logger_ = nullptr;

std::shared_ptr<domain::SeedManager> DependencyFactory::seed_manager_ = nullptr;
std::shared_ptr<domain::ConnectionManager> DependencyFactory::connection_manager_ = nullptr;
std::shared_ptr<domain::AddressPoolManager> DependencyFactory::address_pool_manager_ = nullptr;
std::shared_ptr<domain::SecurityValidator> DependencyFactory::security_validator_ = nullptr;

std::shared_ptr<application::IAuthenticationUseCase> DependencyFactory::auth_use_case_ = nullptr;

std::shared_ptr<domain::ISeedGenerator> DependencyFactory::create_seed_generator() {
    if (!seed_generator_) {
        seed_generator_ = std::make_shared<infrastructure::CryptoSeedGenerator>();
    }
    return seed_generator_;
}

std::shared_ptr<domain::IIPv6AddressManager> DependencyFactory::create_ipv6_manager(const std::string& prefix) {
    if (!ipv6_manager_) {
        ipv6_manager_ = std::make_shared<infrastructure::IPv6AddressManager>(prefix);
    }
    return ipv6_manager_;
}

std::shared_ptr<domain::IConnectionRepository> DependencyFactory::create_connection_repository() {
    if (!connection_repository_) {
        connection_repository_ = std::make_shared<infrastructure::InMemoryConnectionRepository>();
    }
    return connection_repository_;
}

std::shared_ptr<domain::INetworkInterface> DependencyFactory::create_network_interface(const std::string& interface_name) {
    if (!network_interface_) {
        network_interface_ = std::make_shared<infrastructure::LinuxNetworkInterface>(interface_name);
    }
    return network_interface_;
}

std::shared_ptr<domain::ILogger> DependencyFactory::create_logger() {
    if (!logger_) {
        std::string log_path = "/var/log/cspnetwork.log";
        
        try {
            auto& config_manager = CipherProxy::Infrastructure::ConfigManager::instance();
            auto server_config = config_manager.get_server_config();
            if (!server_config.monitoring.log_directory.empty()) {
                log_path = server_config.monitoring.log_directory + "/cspnetwork.log";
            }
        } catch (const std::exception& e) {
            // fallback to default path if config loading fails
        }
        
        auto log_dir = std::filesystem::path(log_path).parent_path();
        std::filesystem::create_directories(log_dir);
        
        logger_ = std::make_shared<infrastructure::FileSystemLogger>(log_path);
    }
    return logger_;
}

std::shared_ptr<domain::SeedManager> DependencyFactory::create_seed_manager() {
    if (!seed_manager_) {
        seed_manager_ = std::make_shared<domain::SeedManager>(create_seed_generator());
    }
    return seed_manager_;
}

std::shared_ptr<domain::ConnectionManager> DependencyFactory::create_connection_manager() {
    if (!connection_manager_) {
        connection_manager_ = std::make_shared<domain::ConnectionManager>(
            create_connection_repository(),
            create_logger()
        );
    }
    return connection_manager_;
}

std::shared_ptr<domain::AddressPoolManager> DependencyFactory::create_address_pool_manager() {
    if (!address_pool_manager_) {
        address_pool_manager_ = std::make_shared<domain::AddressPoolManager>(
            create_ipv6_manager("2001:db8::/32"),
            create_logger()
        );
    }
    return address_pool_manager_;
}

std::shared_ptr<application::ConnectionService> DependencyFactory::create_connection_service() {
    return std::make_shared<application::ConnectionService>(
        create_connection_manager(),
        create_address_pool_manager(),
        create_seed_manager(),
        create_security_validator(),
        create_logger()
    );
}

std::shared_ptr<application::IAddressAllocationUseCase> DependencyFactory::create_address_allocation_use_case() {
    return std::make_shared<application::AddressAllocationUseCase>(
        create_connection_manager(),
        create_address_pool_manager()
    );
}

std::shared_ptr<application::IAuthenticationUseCase> DependencyFactory::create_authentication_use_case() {
    if (!auth_use_case_) {
        auth_use_case_ = std::make_shared<application::AuthenticationUseCase>();
    }
    return auth_use_case_;
}

std::shared_ptr<domain::SecurityValidator> DependencyFactory::create_security_validator() {
    if (!security_validator_) {
        auto crypto_service = std::make_shared<infrastructure::OpenSSLCryptographyService>();
        security_validator_ = std::make_shared<domain::SecurityValidator>(crypto_service, create_logger());
    }
    return security_validator_;
}

}
