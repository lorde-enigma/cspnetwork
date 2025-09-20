#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>
#include "../include/application/vpn_client.h"

std::unique_ptr<seeded_vpn::application::VPNClient> client;
bool running = true;

void signal_handler(int signal) {
    std::cout << "\ndisconnecting..." << std::endl;
    running = false;
    if (client) {
        client->disconnect();
    }
    exit(0);
}

void show_help() {
    std::cout << "csp network vpn client\n\n";
    std::cout << "usage: cspvpn-client [OPTIONS]\n\n";
    std::cout << "options:\n";
    std::cout << "  -c, --config FILE    configuration file (.cspvpn or .yaml)\n";
    std::cout << "  -h, --help          show this help message\n";
    std::cout << "  -v, --version       show version information\n\n";
    std::cout << "examples:\n";
    std::cout << "  cspvpn-client --config client.cspvpn     # connect using .cspvpn config\n";
    std::cout << "  cspvpn-client -c client.yaml             # connect using yaml config\n\n";
    std::cout << "config file formats:\n";
    std::cout << "  .cspvpn format (openvpn-like):\n";
    std::cout << "    remote server.example.com 8080\n";
    std::cout << "    client-id my-client\n";
    std::cout << "    auth-token your-token-here\n";
    std::cout << "    keepalive 30\n";
    std::cout << "    auto-reconnect true\n\n";
    std::cout << "  .yaml format:\n";
    std::cout << "    server:\n";
    std::cout << "      host: server.example.com\n";
    std::cout << "      port: 8080\n";
    std::cout << "    client_id: my-client\n";
    std::cout << "    auth_token: your-token-here\n";
    std::cout << "    keepalive_interval: 30\n";
    std::cout << "    auto_reconnect: true\n";
}

void show_version() {
    std::cout << "csp network vpn client v1.0.0\n";
    std::cout << "compatible with csp network server\n";
    std::cout << "c++20 implementation\n";
}

std::string status_to_string(seeded_vpn::application::ConnectionStatus status) {
    switch (status) {
        case seeded_vpn::application::ConnectionStatus::DISCONNECTED: return "disconnected";
        case seeded_vpn::application::ConnectionStatus::CONNECTING: return "connecting";
        case seeded_vpn::application::ConnectionStatus::CONNECTED: return "connected";
        case seeded_vpn::application::ConnectionStatus::RECONNECTING: return "reconnecting";
        case seeded_vpn::application::ConnectionStatus::ERROR: return "error";
        default: return "unknown";
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::string config_file;

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
        else if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_file = argv[++i];
        }
        else if (arg.starts_with("-")) {
            std::cerr << "error: unknown option: " << arg << std::endl;
            std::cerr << "use --help for usage information" << std::endl;
            return 1;
        }
        else {
            config_file = arg;
        }
    }

    if (config_file.empty()) {
        std::cerr << "error: configuration file required" << std::endl;
        std::cerr << "use --help for usage information" << std::endl;
        return 1;
    }

    try {
        client = std::make_unique<seeded_vpn::application::VPNClient>();

        client->set_status_callback([](seeded_vpn::application::ConnectionStatus status, const std::string& message) {
            std::cout << "[" << status_to_string(status) << "] " << message << std::endl;
        });

        client->set_data_callback([](const std::vector<uint8_t>& data) {
            std::cout << "received " << data.size() << " bytes" << std::endl;
        });

        std::cout << "loading configuration from: " << config_file << std::endl;
        
        if (!client->load_config(config_file)) {
            std::cerr << "error: failed to load config: " << client->get_last_error() << std::endl;
            return 1;
        }

        std::cout << "connecting to vpn server..." << std::endl;
        
        auto connect_future = client->connect();
        auto status = connect_future.wait_for(std::chrono::seconds(30));
        
        if (status == std::future_status::timeout) {
            std::cerr << "error: connection timeout" << std::endl;
            return 1;
        }

        if (!connect_future.get()) {
            std::cerr << "error: connection failed: " << client->get_last_error() << std::endl;
            return 1;
        }

        std::cout << "connected successfully!" << std::endl;
        std::cout << "vpn tunnel established - press ctrl+c to disconnect" << std::endl;

        while (running && client->is_connected()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        if (client->is_connected()) {
            std::cout << "disconnecting..." << std::endl;
            client->disconnect();
        }

    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "vpn client terminated" << std::endl;
    return 0;
}
