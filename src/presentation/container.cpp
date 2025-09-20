#include "../../include/presentation/container.h"
#include "../../include/infrastructure/repositories.h"
#include "../../include/infrastructure/config_manager.h"
#include "../../include/application/services.h"
#include <stdexcept>
#include <filesystem>

namespace seeded_vpn::presentation {

DependencyContainer& DependencyContainer::instance() {
    static DependencyContainer container;
    return container;
}

void DependencyContainer::initialize(const std::string& config_file_path) {
    if (initialized_) {
        return;
    }
    
    config_file_path_ = config_file_path;
    
    auto& config_manager = CipherProxy::Infrastructure::ConfigManager::instance();
    config_manager.initialize(config_file_path);
    
    std::string log_file_path = "/var/log/cspnetwork.log";
    domain::LogLevel log_level = domain::LogLevel::INFO;
    
    try {
        auto server_config = config_manager.get_server_config();
        log_file_path = server_config.monitoring.log_directory + "/cspnetwork.log";
        
        if (server_config.monitoring.log_level == "TRACE") {
            log_level = domain::LogLevel::TRACE;
        } else if (server_config.monitoring.log_level == "WARNING") {
            log_level = domain::LogLevel::WARNING;
        } else if (server_config.monitoring.log_level == "ERROR") {
            log_level = domain::LogLevel::ERROR;
        } else if (server_config.monitoring.log_level == "CRITICAL") {
            log_level = domain::LogLevel::CRITICAL;
        }
        
        std::filesystem::create_directories(std::filesystem::path(log_file_path).parent_path());
    } catch (const std::exception& e) {
        std::cerr << "warning: failed to load config, using defaults: " << e.what() << std::endl;
    }
    
    logger_ = std::make_shared<infrastructure::FileSystemLogger>(log_file_path, log_level);
    connection_repository_ = std::make_shared<infrastructure::InMemoryConnectionRepository>();
    
    auto seed_generator = std::make_shared<infrastructure::ConcreteSeedGenerator>();
    
    domain::IPv6Address base_prefix = {};
    auto address_manager = std::make_shared<infrastructure::MemoryPoolIPv6Manager>(base_prefix, 64);
    auto crypto_service = std::make_shared<infrastructure::OpenSSLCryptographyService>();
    
    connection_manager_ = std::make_shared<domain::ConnectionManager>(connection_repository_, logger_);
    address_pool_manager_ = std::make_shared<domain::AddressPoolManager>(address_manager, logger_);
    seed_manager_ = std::make_shared<domain::SeedManager>(seed_generator);
    security_validator_ = std::make_shared<domain::SecurityValidator>(crypto_service, logger_);
    
    connection_service_ = std::make_shared<application::ConnectionService>(
        connection_manager_,
        address_pool_manager_,
        seed_manager_,
        security_validator_,
        logger_
    );
    
    initialized_ = true;
}

std::shared_ptr<domain::IConnectionRepository> DependencyContainer::get_connection_repository() {
    if (!connection_repository_) {
        throw std::runtime_error("connection repository not initialized");
    }
    return connection_repository_;
}

std::shared_ptr<application::ConnectionService> DependencyContainer::get_connection_service() {
    if (!connection_service_) {
        throw std::runtime_error("connection service not initialized");
    }
    return connection_service_;
}

std::shared_ptr<domain::ILogger> DependencyContainer::get_logger() {
    if (!logger_) {
        throw std::runtime_error("logger not initialized");
    }
    return logger_;
}

std::shared_ptr<domain::ConnectionManager> DependencyContainer::get_connection_manager() {
    if (!connection_manager_) {
        throw std::runtime_error("connection manager not initialized");
    }
    return connection_manager_;
}

std::shared_ptr<domain::AddressPoolManager> DependencyContainer::get_address_pool_manager() {
    if (!address_pool_manager_) {
        throw std::runtime_error("address pool manager not initialized");
    }
    return address_pool_manager_;
}

std::shared_ptr<domain::SeedManager> DependencyContainer::get_seed_manager() {
    if (!seed_manager_) {
        throw std::runtime_error("seed manager not initialized");
    }
    return seed_manager_;
}

std::shared_ptr<domain::SecurityValidator> DependencyContainer::get_security_validator() {
    if (!security_validator_) {
        throw std::runtime_error("security validator not initialized");
    }
    return security_validator_;
}

}
