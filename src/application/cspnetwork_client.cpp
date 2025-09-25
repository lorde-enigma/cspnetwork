#include "../include/application/cspnetwork_client.h"
#include "../include/infrastructure/tun_interface.h"

using namespace seeded_vpn;
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <yaml-cpp/yaml.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

namespace cspnetwork::application {

class CSPNetworkClientImpl {
public:
    CSPNetworkClientImpl(CSPNetworkClient* parent) : parent_(parent), connected_(false), tun_interface_(std::make_unique<seeded_vpn::infrastructure::TunInterface>()) {}
    
    std::future<bool> connect(const ClientConfig& config) {
        auto promise = std::make_shared<std::promise<bool>>();
        auto future = promise->get_future();
        
        std::thread([this, config, promise]() {
            parent_->update_status(ConnectionStatus::CONNECTING, "connecting to " + config.server_host);
            
            seeded_vpn::infrastructure::TunConfig tun_config;
            tun_config.device_name = "cspnet0";
            tun_config.local_ip = "10.8.0.2";
            tun_config.netmask = "24";
            tun_config.mtu = 1500;
            
            if (!tun_interface_->create_tun(tun_config)) {
                parent_->update_status(ConnectionStatus::DISCONNECTED, "failed to create tunnel interface");
                promise->set_value(false);
                return;
            }
            
            parent_->update_status(ConnectionStatus::CONNECTING, "authenticating");
            
            if (!test_connection(config.server_host, config.server_port)) {
                parent_->update_status(ConnectionStatus::DISCONNECTED, "failed to connect to server");
                tun_interface_->destroy_tun();
                promise->set_value(false);
                return;
            }
            
            tun_interface_->set_packet_callback([this](const std::vector<uint8_t>& packet) {
                handle_packet(packet);
            });
            
            tun_interface_->start_packet_loop();
            
            // Comentado para teste - não capturar rota default
            // if (!tun_interface_->add_route("0.0.0.0/1", "10.8.0.1")) {
            //     std::cerr << "warning: failed to add default route" << std::endl;
            // }
            
            connected_ = true;
            parent_->update_status(ConnectionStatus::CONNECTED, "tunnel established on " + tun_interface_->get_device_name());
            promise->set_value(true);
        }).detach();
        
        return future;
    }
    
    void disconnect() {
        if (connected_ && tun_interface_) {
            tun_interface_->stop_packet_loop();
            // tun_interface_->remove_route("0.0.0.0/1");
            tun_interface_->destroy_tun();
        }
        connected_ = false;
        parent_->update_status(ConnectionStatus::DISCONNECTED, "tunnel destroyed");
    }
    
    bool is_connected() const {
        return connected_ && tun_interface_ && tun_interface_->is_active();
    }
    
    std::future<bool> send_data(const std::vector<uint8_t>& data) {
        auto promise = std::make_shared<std::promise<bool>>();
        auto future = promise->get_future();
        
        if (connected_ && tun_interface_) {
            promise->set_value(tun_interface_->send_packet(data));
        } else {
            promise->set_value(false);
        }
        
        return future;
    }
    
    void handle_packet(const std::vector<uint8_t>& packet) {
        if (connected_) {
            std::cout << "received packet: " << packet.size() << " bytes" << std::endl;
        }
    }
    
    bool test_connection(const std::string& host, int port) {
        int sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sock < 0) {
            sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) return false;
        }
        
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr* addr_ptr = nullptr;
        socklen_t addr_len = 0;
        
        if (inet_pton(AF_INET6, host.c_str(), &addr6.sin6_addr) == 1) {
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(port);
            addr_ptr = reinterpret_cast<struct sockaddr*>(&addr6);
            addr_len = sizeof(addr6);
        } else if (inet_pton(AF_INET, host.c_str(), &addr4.sin_addr) == 1) {
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(port);
            addr_ptr = reinterpret_cast<struct sockaddr*>(&addr4);
            addr_len = sizeof(addr4);
        } else {
            close(sock);
            return false;
        }
        
        struct timeval timeout;
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        const char test_msg[] = "ping";
        ssize_t sent = sendto(sock, test_msg, strlen(test_msg), 0, addr_ptr, addr_len);
        
        close(sock);
        return sent > 0;
    }

private:
    CSPNetworkClient* parent_;
    bool connected_;
    std::unique_ptr<seeded_vpn::infrastructure::TunInterface> tun_interface_;
};

CSPNetworkClient::CSPNetworkClient() : impl_(std::make_unique<CSPNetworkClientImpl>(this)), status_(ConnectionStatus::DISCONNECTED) {}

CSPNetworkClient::~CSPNetworkClient() = default;

bool CSPNetworkClient::load_config(const std::string& config_file) {
    return parse_config_file(config_file);
}

std::future<bool> CSPNetworkClient::connect() {
    return impl_->connect(config_);
}

void CSPNetworkClient::disconnect() {
    impl_->disconnect();
}

bool CSPNetworkClient::is_connected() const {
    return impl_->is_connected();
}

void CSPNetworkClient::set_status_callback(StatusCallback callback) {
    status_callback_ = callback;
}

void CSPNetworkClient::set_data_callback(DataCallback callback) {
    data_callback_ = callback;
}

std::future<bool> CSPNetworkClient::send_data(const std::vector<uint8_t>& data) {
    return impl_->send_data(data);
}

ConnectionStatus CSPNetworkClient::get_status() const {
    return status_;
}

std::string CSPNetworkClient::get_last_error() const {
    return last_error_;
}

bool CSPNetworkClient::parse_config_file(const std::string& config_file) {
    try {
        if (config_file.length() >= 7 && config_file.substr(config_file.length() - 7) == ".cspvpn") {
            return parse_csp_config(config_file);
        } else if ((config_file.length() >= 5 && config_file.substr(config_file.length() - 5) == ".yaml") || 
                   (config_file.length() >= 4 && config_file.substr(config_file.length() - 4) == ".yml")) {
            return parse_yaml_config(config_file);
        } else {
            last_error_ = "unsupported config file format";
            return false;
        }
    } catch (const std::exception& e) {
        last_error_ = std::string("config parse error: ") + e.what();
        return false;
    }
}

bool CSPNetworkClient::parse_csp_config(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        last_error_ = "cannot open config file: " + config_file;
        return false;
    }

    std::string line;
    config_ = ClientConfig{};
    config_.server_port = 8080;
    config_.auto_reconnect = true;
    config_.keepalive_interval = 60;
    config_.connection_timeout = 30;
    config_.protocol = "tcp";
    config_.log_level = "info";

    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        if (line.length() > 7 && line.substr(0, 7) == "remote ") {
            std::istringstream iss(line);
            std::string keyword, host;
            uint16_t port;
            if (iss >> keyword >> host >> port) {
                config_.server_host = host;
                config_.server_port = port;
            }
        } else if (line.length() >= 14 && line.substr(0, 14) == "auth-user-pass") {
            std::istringstream iss(line);
            std::string keyword, auth_file;
            if (iss >> keyword >> auth_file) {
                std::ifstream auth(auth_file);
                if (auth.is_open()) {
                    std::getline(auth, config_.client_id);
                    std::getline(auth, config_.auth_token);
                }
            }
        } else if (line.length() >= 6 && line.substr(0, 6) == "proto ") {
            std::istringstream iss(line);
            std::string keyword, protocol;
            if (iss >> keyword >> protocol) {
                config_.protocol = protocol;
            }
        } else if (line.length() >= 10 && line.substr(0, 10) == "keepalive ") {
            std::istringstream iss(line);
            std::string keyword;
            uint32_t interval;
            if (iss >> keyword >> interval) {
                config_.keepalive_interval = interval;
            }
        }
    }

    if (config_.server_host.empty()) {
        last_error_ = "missing server host in config";
        return false;
    }

    return true;
}

bool CSPNetworkClient::parse_yaml_config(const std::string& config_file) {
    try {
        YAML::Node config_node = YAML::LoadFile(config_file);
        
        config_ = ClientConfig{};
        config_.server_host = config_node["server"]["host"].as<std::string>();
        config_.server_port = config_node["server"]["port"].as<uint16_t>(8080);
        config_.client_id = config_node["auth"]["client_id"].as<std::string>();
        config_.auth_token = config_node["auth"]["token"].as<std::string>();
        config_.protocol = config_node["protocol"].as<std::string>("tcp");
        config_.auto_reconnect = config_node["auto_reconnect"].as<bool>(true);
        config_.keepalive_interval = config_node["keepalive_interval"].as<uint32_t>(60);
        config_.connection_timeout = config_node["connection_timeout"].as<uint32_t>(30);
        config_.log_level = config_node["log_level"].as<std::string>("info");

        if (config_.server_host.empty() || config_.client_id.empty()) {
            last_error_ = "missing required config fields";
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        last_error_ = std::string("yaml parse error: ") + e.what();
        return false;
    }
}

void CSPNetworkClient::update_status(ConnectionStatus status, const std::string& message) {
    status_ = status;
    if (!message.empty()) {
        last_error_ = message;
    }
    if (status_callback_) {
        status_callback_(status, message);
    }
}

}
