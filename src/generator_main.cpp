#include "../include/application/client_generator.h"
#include "../include/infrastructure/config_manager.h"
#include "../include/infrastructure/repositories.h"
#include "../include/domain/entities.h"
#include <iostream>
#include <fstream>
#include <string>

using namespace seeded_vpn;

void print_usage() {
    std::cout << "CSP Network VPN - Client Generator\n";
    std::cout << "Usage: cspvpn-gen [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --name <name>         Client name (required)\n";
    std::cout << "  --seed <seed>         Custom seed (optional)\n";
    std::cout << "  --format <format>     Config format: cspvpn|yaml (default: cspvpn)\n";
    std::cout << "  --output <file>       Output file (default: stdout)\n";
    std::cout << "  --list                List active clients\n";
    std::cout << "  --revoke <client-id>  Revoke client access\n";
    std::cout << "  --help                Show this help\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string name;
    std::string seed;
    std::string format = "cspvpn";
    std::string output_file;
    std::string revoke_client;
    bool list_clients = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help") {
            print_usage();
            return 0;
        } else if (arg == "--list") {
            list_clients = true;
        } else if (arg == "--name" && i + 1 < argc) {
            name = argv[++i];
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = argv[++i];
        } else if (arg == "--format" && i + 1 < argc) {
            format = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--revoke" && i + 1 < argc) {
            revoke_client = argv[++i];
        }
    }

    try {
        auto logger = std::make_shared<infrastructure::FileLogger>("client_generator.log");
        auto config_manager = std::make_shared<infrastructure::ConfigManager>();
        config_manager->load_from_file("config/default.yaml");
        
        auto seed_generator = std::make_shared<infrastructure::SeededGenerator>();
        auto seed_manager = std::make_shared<domain::SeedManager>(seed_generator);
        auto address_manager = std::make_shared<infrastructure::IPv6AddressRepository>();
        auto address_pool_manager = std::make_shared<domain::AddressPoolManager>(address_manager, logger);
        
        auto client_generator = std::make_shared<application::ClientGeneratorService>(
            seed_manager, address_pool_manager, logger);

        if (list_clients) {
            auto clients = client_generator->list_active_clients();
            std::cout << "Active clients:\n";
            for (const auto& client : clients) {
                std::cout << "  " << client << "\n";
            }
            return 0;
        }

        if (!revoke_client.empty()) {
            if (client_generator->revoke_client(revoke_client)) {
                std::cout << "Client revoked: " << revoke_client << "\n";
            } else {
                std::cerr << "Failed to revoke client: " << revoke_client << "\n";
                return 1;
            }
            return 0;
        }

        if (name.empty()) {
            std::cerr << "Error: --name is required\n";
            print_usage();
            return 1;
        }

        application::ClientGenerationRequest request;
        request.client_name = name;
        request.requested_seed = seed;
        request.config_format = format;

        auto config = client_generator->generate_client(request);

        std::cout << "Generated client configuration:\n";
        std::cout << "Client ID: " << config.client_id << "\n";
        std::cout << "Seed: " << config.seed << "\n";
        std::cout << "Exit IP: " << config.exit_ip << "\n";
        std::cout << "Auth Token: " << config.auth_token << "\n\n";

        if (!output_file.empty()) {
            std::ofstream file(output_file);
            if (file.is_open()) {
                file << config.config_content;
                file.close();
                std::cout << "Configuration saved to: " << output_file << "\n";
            } else {
                std::cerr << "Error: Could not write to file: " << output_file << "\n";
                return 1;
            }
        } else {
            std::cout << "Configuration file content:\n";
            std::cout << "---\n" << config.config_content << "---\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
