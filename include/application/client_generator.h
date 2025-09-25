#pragma once

#include "../domain/entities.h"
#include "../domain/interfaces.h"
#include <memory>
#include <string>

namespace seeded_vpn::application {

struct ClientGenerationRequest {
    std::string client_name;
    std::string requested_seed;
    std::string config_format = "cspvpn";
};

struct ClientConfiguration {
    std::string client_id;
    std::string seed;
    std::string exit_ip;
    std::string config_content;
    std::string auth_token;
};

class ClientGeneratorService {
public:
    ClientGeneratorService(
        std::shared_ptr<domain::SeedManager> seed_manager,
        std::shared_ptr<domain::AddressPoolManager> address_pool_manager,
        std::shared_ptr<domain::ILogger> logger
    );
    
    ClientConfiguration generate_client(const ClientGenerationRequest& request);
    std::string generate_config_file(const ClientConfiguration& config, const std::string& format);
    void generate_client_config(const std::string& client_name, const std::string& output_dir);
    bool revoke_client(const std::string& client_id);
    std::vector<std::string> list_active_clients();

private:
    std::string generate_client_id(const std::string& name);
    std::string generate_auth_token();
    std::string create_cspvpn_config(const ClientConfiguration& config);
    std::string create_yaml_config(const ClientConfiguration& config);
    
    std::shared_ptr<domain::SeedManager> seed_manager_;
    std::shared_ptr<domain::AddressPoolManager> address_pool_manager_;
    std::shared_ptr<domain::ILogger> logger_;
};

}
