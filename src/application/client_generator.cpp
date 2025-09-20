#include "../include/application/client_generator.h"
#include "../include/infrastructure/seed_generator.h"
#include <random>
#include <sstream>
#include <chrono>
#include <iomanip>

namespace seeded_vpn::application {

ClientGeneratorService::ClientGeneratorService() {}

ClientGeneratorService::~ClientGeneratorService() = default;

ClientConfiguration ClientGeneratorService::generate_client(const ClientGenerationRequest& request) {
    ClientConfiguration config;
    config.client_id = generate_client_id(request.client_name);
    config.client_name = request.client_name;
    
    auto seed = request.seed.empty() ? generate_seed() : request.seed;
    config.seed = seed;
    
    config.exit_ip = seed_to_exit_ip(seed);
    config.local_ip = "10.8.0.100";
    config.server_host = "127.0.0.1";
    config.server_port = 8080;
    
    config.private_key = generate_private_key();
    config.public_key = generate_public_key(config.private_key);
    config.server_public_key = get_server_public_key();
    
    return config;
}

std::string ClientGeneratorService::generate_config_file(const ClientConfiguration& config, const std::string& format) {
    if (format == "yaml") {
        return create_yaml_config(config);
    } else {
        return create_cspvpn_config(config);
    }
}

std::string ClientGeneratorService::create_cspvpn_config(const ClientConfiguration& config) {
    std::ostringstream oss;
    oss << "# csp network vpn client configuration\n";
    oss << "# generated client configuration\n\n";
    oss << "# server connection\n";
    oss << "remote localhost 8080\n\n";
    oss << "# client identification\n";
    oss << "client-id " << config.client_id << "\n";
    oss << "auth-token " << config.auth_token << "\n";
    oss << "client-seed " << config.seed << "\n";
    oss << "exit-ip " << config.exit_ip << "\n\n";
    oss << "# connection settings\n";
    oss << "protocol tcp\n";
    oss << "keepalive 30\n";
    oss << "connect-timeout 10\n";
    oss << "auto-reconnect true\n\n";
    oss << "# logging\n";
    oss << "log-level info\n\n";
    oss << "# routes will be managed by seed-based exit ip\n";
    return oss.str();
}

std::string ClientGeneratorService::create_yaml_config(const ClientConfiguration& config) {
    std::ostringstream oss;
    oss << "# csp network vpn client configuration (yaml format)\n";
    oss << "server:\n";
    oss << "  host: localhost\n";
    oss << "  port: 8080\n";
    oss << "  protocol: tcp\n\n";
    oss << "client:\n";
    oss << "  id: " << config.client_id << "\n";
    oss << "  auth_token: " << config.auth_token << "\n";
    oss << "  seed: " << config.seed << "\n";
    oss << "  exit_ip: " << config.exit_ip << "\n\n";
    oss << "connection:\n";
    oss << "  keepalive: 30\n";
    oss << "  timeout: 10\n";
    oss << "  auto_reconnect: true\n\n";
    oss << "logging:\n";
    oss << "  level: info\n";
    return oss.str();
}

std::string ClientGeneratorService::generate_client_id(const std::string& name) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << name << "-" << std::put_time(std::gmtime(&time_t), "%Y%m%d-%H%M%S");
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    oss << "-" << dis(gen);
    
    return oss.str();
}

std::string ClientGeneratorService::generate_auth_token() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::ostringstream oss;
    oss << "csp-token-";
    for (int i = 0; i < 32; ++i) {
        oss << std::hex << dis(gen);
    }
    
    return oss.str();
}

std::string ClientGeneratorService::generate_seed() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::ostringstream oss;
    for (int i = 0; i < 32; ++i) {
        oss << std::hex << dis(gen);
    }
    
    return oss.str();
}

std::string ClientGeneratorService::seed_to_exit_ip(const std::string& seed) {
    std::hash<std::string> hasher;
    auto hash = hasher(seed);
    
    uint8_t ip[4];
    ip[0] = 10;
    ip[1] = (hash >> 16) & 0xFF;
    ip[2] = (hash >> 8) & 0xFF;
    ip[3] = hash & 0xFF;
    
    return std::to_string(ip[0]) + "." + 
           std::to_string(ip[1]) + "." + 
           std::to_string(ip[2]) + "." + 
           std::to_string(ip[3]);
}

std::string ClientGeneratorService::generate_private_key() {
    return "private-key-placeholder";
}

std::string ClientGeneratorService::generate_public_key(const std::string& private_key) {
    return "public-key-" + private_key.substr(0, 8);
}

std::string ClientGeneratorService::get_server_public_key() {
    return "server-public-key-placeholder";
}

bool ClientGeneratorService::revoke_client(const std::string& client_id) {
    return true;
}

std::vector<std::string> ClientGeneratorService::list_active_clients() {
    return {};
}

}
