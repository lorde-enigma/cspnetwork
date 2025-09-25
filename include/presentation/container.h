#pragma once

#include "../domain/interfaces.h"
#include "../application/use_cases.h"
#include "../application/services.h"
#include "../application/client_generator.h"
#include "../infrastructure/repositories.h"
#include <memory>
#include <string>

namespace seeded_vpn::presentation {

class DependencyContainer {
public:
    static DependencyContainer& instance();
    
    void initialize(const std::string& config_file_path = "/etc/cspnetwork/config.yaml");
    
    std::shared_ptr<domain::IConnectionRepository> get_connection_repository();
    std::shared_ptr<application::ConnectionService> get_connection_service();
    std::shared_ptr<domain::ILogger> get_logger();
    std::shared_ptr<domain::ConnectionManager> get_connection_manager();
    std::shared_ptr<domain::AddressPoolManager> get_address_pool_manager();
    std::shared_ptr<domain::SeedManager> get_seed_manager();
    std::shared_ptr<domain::SecurityValidator> get_security_validator();
    std::shared_ptr<application::ClientGeneratorService> get_client_generator_service();

private:
    DependencyContainer() = default;
    ~DependencyContainer() = default;
    DependencyContainer(const DependencyContainer&) = delete;
    DependencyContainer& operator=(const DependencyContainer&) = delete;
    
    bool initialized_ = false;
    std::string config_file_path_;
    
    std::shared_ptr<domain::IConnectionRepository> connection_repository_;
    std::shared_ptr<application::ConnectionService> connection_service_;
    std::shared_ptr<domain::ILogger> logger_;
    std::shared_ptr<domain::ConnectionManager> connection_manager_;
    std::shared_ptr<domain::AddressPoolManager> address_pool_manager_;
    std::shared_ptr<domain::SeedManager> seed_manager_;
    std::shared_ptr<domain::SecurityValidator> security_validator_;
    std::shared_ptr<application::ClientGeneratorService> client_generator_service_;
};

}
