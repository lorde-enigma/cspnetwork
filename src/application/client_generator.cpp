#include "../include/application/client_generator.h"
#include "../include/infrastructure/seed_generator.h"
#include "../include/infrastructure/seeded_connection_manager.h"
#include "../include/infrastructure/repositories.h"
#include <random>
#include <sstream>
#include <chrono>
#include <iomanip>

namespace seeded_vpn::application {

ClientGeneratorService::ClientGeneratorService(
    std::shared_ptr<domain::SeedManager> seed_manager,
    std::shared_ptr<domain::AddressPoolManager> address_pool_manager,
    std::shared_ptr<domain::ILogger> logger
) : seed_manager_(seed_manager), 
    address_pool_manager_(address_pool_manager), 
    logger_(logger) {}

ClientConfiguration ClientGeneratorService::generate_client(const ClientGenerationRequest& request) {
    logger_->info("generating client configuration for: " + request.client_name);
    
    ClientConfiguration config;
    config.client_id = generate_client_id(request.client_name);
    config.auth_token = generate_auth_token();
    
    domain::SeedValue seed_value;
    if (!request.requested_seed.empty()) {
        seed_value = std::stoull(request.requested_seed);
        config.seed = request.requested_seed;
        logger_->info("using requested seed: " + config.seed);
    } else {
        seed_value = seed_manager_->generate_seed_for_client(config.client_id, 0);
        config.seed = std::to_string(seed_value);
        logger_->info("generated seed: " + config.seed);
    }
    
    auto seed_gen = std::make_shared<infrastructure::ConcreteSeedGenerator>();
    infrastructure::SeededConnectionManager connection_manager(seed_gen);
    
    infrastructure::SeededConnectionManager::ConnectionConfig conn_config;
    conn_config.clientId = config.client_id;
    conn_config.interfaceName = "tun0";
    conn_config.strategy = domain::SeedStrategy::PER_CONNECTION;
    conn_config.enableStealth = true;
    conn_config.sessionTimeout = 3600;
    
    auto connection_id = connection_manager.establishConnection(conn_config);
    auto connection = connection_manager.getConnection(connection_id);
    
    if (connection) {
        std::ostringstream oss;
        const auto& addr = connection->assignedAddress;
        oss << std::hex;
        for (size_t i = 0; i < addr.size(); i += 2) {
            if (i > 0) oss << ":";
            oss << std::setfill('0') << std::setw(2) << static_cast<int>(addr[i]);
            oss << std::setfill('0') << std::setw(2) << static_cast<int>(addr[i+1]);
        }
        config.exit_ip = oss.str();
    } else {
        throw std::runtime_error("failed to establish connection for client");
    }
    
    config.config_content = generate_config_file(config, request.config_format);
    
    logger_->info("client generated - id: " + config.client_id + ", exit_ip: " + config.exit_ip);
    
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

bool ClientGeneratorService::revoke_client(const std::string& client_id) {
    logger_->info("revoking client: " + client_id);
    return true;
}

std::vector<std::string> ClientGeneratorService::list_active_clients() {
    return {};
}

}
