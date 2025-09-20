#include <iostream>
#include <signal.h>
#include <thread>
#include <chrono>
#include "../include/presentation/server.h"
#include "../include/presentation/container.h"

std::unique_ptr<seeded_vpn::presentation::VPNRestServer> server;

void signal_handler(int signal) {
    if (server) {
        std::cout << "\nshutting down server..." << std::endl;
        server->stop();
    }
    exit(0);
}

void show_help() {
    std::cout << "ciphers systems private network\n\n";
    std::cout << "usage: cspnetwork [OPTIONS]\n\n";
    std::cout << "options:\n";
    std::cout << "  -p, --port PORT      set server port (default: 8080)\n";
    std::cout << "  -c, --config FILE    set configuration file path\n";
    std::cout << "  -h, --help           show this help message\n";
    std::cout << "  -v, --version        show version information\n\n";
    std::cout << "examples:\n";
    std::cout << "  cspnetwork                              # run on default port 8080\n";
    std::cout << "  cspnetwork -p 9000                      # run on port 9000\n";
    std::cout << "  cspnetwork --config /etc/vpn/config.yaml  # use custom config\n";
}

void show_version() {
    std::cout << "Ciphers Systems Private Network v1.0.0\n";
    std::cout << "built with Clean Architecture principles\n";
    std::cout << "C++20 implementation with high-performance networking\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    try {
        uint16_t port = 8080;
        std::string config_file = "config.yaml";
        
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            
            if (arg == "-h" || arg == "--help") {
                show_help();
                return 0;
            }
            else if (arg == "-v" || arg == "--version") {
                show_version();
                return 0;
            }
            else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
                try {
                    port = static_cast<uint16_t>(std::stoi(argv[++i]));
                } catch (const std::exception&) {
                    std::cerr << "error: invalid port number: " << argv[i] << std::endl;
                    return 1;
                }
            }
            else if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
                config_file = argv[++i];
            }
            else if (arg.starts_with("-")) {
                std::cerr << "error: unknown option: " << arg << std::endl;
                std::cerr << "use --help for usage information" << std::endl;
                return 1;
            }
            else {
                try {
                    port = static_cast<uint16_t>(std::stoi(arg));
                } catch (const std::exception&) {
                    std::cerr << "error: invalid port number: " << arg << std::endl;
                    return 1;
                }
            }
        }
        
        std::cout << "seeded vpn server starting..." << std::endl;
        
        auto& container = seeded_vpn::presentation::DependencyContainer::instance();
        container.initialize(config_file);
        
        server = std::make_unique<seeded_vpn::presentation::VPNRestServer>(port);
        server->start();
        
        std::cout << "seeded vpn server running on port " << port << std::endl;
        std::cout << "press ctrl+c to stop" << std::endl;
        
        while (server->is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
