#pragma once

#include "../domain/entities.h"
#include "../domain/interfaces.h"
#include <memory>
#include <string>

namespace seeded_vpn::application {

struct ClientGenerationRequest {
    std::string client_name;
    std::string seed;
    std::string format = "cspvpn";
};

struct ClientConfiguration {
    std::string client_id;
    std::string client_name;
    std::string seed;
    std::string exit_ip;
    std::string local_ip;
    std::string server_host;
    int server_port;
    std::string private_key;
    std::string public_key;
    std::string server_public_key;
    std::string auth_token;
};

class ClientGeneratorService {
public:
    ClientGeneratorService();
    ~ClientGeneratorService();
    
    ClientConfiguration generate_client(const ClientGenerationRequest& request);
    std::string generate_config_file(const ClientConfiguration& config, const std::string& format);
    bool revoke_client(const std::string& client_id);
    std::vector<std::string> list_active_clients();

private:
    std::string generate_client_id(const std::string& name);
    std::string generate_auth_token();
    std::string generate_seed();
    std::string seed_to_exit_ip(const std::string& seed);
    std::string generate_private_key();
    std::string generate_public_key(const std::string& private_key);
    std::string get_server_public_key();
    std::string create_cspvpn_config(const ClientConfiguration& config);
    std::string create_yaml_config(const ClientConfiguration& config);
};

}
