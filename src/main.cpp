#include <iostream>
#include <signal.h>
#include <thread>
#include <chrono>
#include "../include/presentation/udp_tunnel_server.h"
#include "../include/domain/vpn_config.h"

std::unique_ptr<seeded_vpn::presentation::UDPTunnelServer> server;

void signal_handler(int sig) {
    std::cout << "\nreceived signal " << sig << ", shutting down server..." << std::endl;
    if (server) {
        server->stop();
    }
    exit(0);
}

void show_help() {
    std::cout << "ciphers systems private network - udp tunnel mode\n\n";
    std::cout << "usage: cspnetwork [OPTIONS]\n\n";
    std::cout << "options:\n";
    std::cout << "  -p, --port PORT      set tunnel server port (default: 1194)\n";
    std::cout << "  -c, --config FILE    set configuration file path\n";
    std::cout << "  -h, --help           show this help message\n";
    std::cout << "  -v, --version        show version information\n\n";
    std::cout << "examples:\n";
    std::cout << "  cspnetwork                              # run on default port 1194\n";
    std::cout << "  cspnetwork -p 9000                      # run on port 9000\n";
    std::cout << "  cspnetwork --config /etc/vpn/config.yaml  # use custom config\n";
}

void show_version() {
    std::cout << "Ciphers Systems Private Network v2.0.0 - UDP Tunnel Mode\n";
    std::cout << "built with Clean Architecture principles\n";
    std::cout << "C++20 implementation with high-performance UDP tunneling\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    try {
        uint16_t port = 1194;
        std::string config_file = "config/default.yaml";
        
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
        
        std::cout << "seeded vpn udp tunnel server starting..." << std::endl;
        
        auto config = std::make_shared<seeded_vpn::domain::VPNConfig>(config_file);
        config->set_server_port(port);
        
        server = std::make_unique<seeded_vpn::presentation::UDPTunnelServer>(config);
        server->start();
        
        std::cout << "seeded vpn udp tunnel server running on port " << port << std::endl;
        std::cout << "tunnel interface: " << config->get_tunnel_interface_name() << std::endl;
        std::cout << "ip range: " << config->get_ip_range() << std::endl;
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
