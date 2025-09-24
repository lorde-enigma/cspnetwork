#include "../include/application/vpn_client.h"
#include "../include/infrastructure/tun_interface.h"
#include <iostream>
#include <fstream>
#include <regex>
#include <thread>
#include <chrono>
#include <yaml-cpp/yaml.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>

namespace seeded_vpn::application {

class VPNClientImpl {
public:
    VPNClientImpl(VPNClient* parent) : parent_(parent), connected_(false), tun_interface_(std::make_unique<infrastructure::TunInterface>()) {}
    
    std::future<bool> connect(const ClientConfig& config) {
        auto promise = std::make_shared<std::promise<bool>>();
        auto future = promise->get_future();
        
        std::thread([this, config, promise]() {
            parent_->update_status(ConnectionStatus::CONNECTING, "connecting to " + config.server_host);
            
            infrastructure::TunConfig tun_config;
            tun_config.device_name = "cspvpn0";
            tun_config.local_ip = "10.8.0.2";
            tun_config.netmask = "24";
            tun_config.mtu = 1500;
            
            if (!tun_interface_->create_tun(tun_config)) {
                parent_->update_status(ConnectionStatus::DISCONNECTED, "failed to create tun interface");
                promise->set_value(false);
                return;
            }
            
            parent_->update_status(ConnectionStatus::CONNECTING, "authenticating");
            
            std::cout << "testing server connection to " << config.server_host << ":" << config.server_port << std::endl;
            if (!test_server_connection(config.server_host, config.server_port)) {
                std::cout << "server connection test failed!" << std::endl;
                parent_->update_status(ConnectionStatus::DISCONNECTED, "failed to connect to server");
                tun_interface_->destroy_tun();
                promise->set_value(false);
                return;
            }
            std::cout << "server connection test passed!" << std::endl;
            
            tun_interface_->set_packet_callback([this](const std::vector<uint8_t>& packet) {
                handle_tun_packet(packet);
            });
            
            tun_interface_->start_packet_loop();
            
            if (!tun_interface_->add_route("0.0.0.0/1", "10.8.0.1")) {
                std::cerr << "warning: failed to add default route" << std::endl;
            }
            
            connected_ = true;
            parent_->update_status(ConnectionStatus::CONNECTED, "tunnel established on " + tun_interface_->get_device_name());
            promise->set_value(true);
        }).detach();
        
        return future;
    }
    
    void disconnect() {
        if (connected_ && tun_interface_) {
            tun_interface_->stop_packet_loop();
            tun_interface_->remove_route("0.0.0.0/1");
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
    
    void handle_tun_packet(const std::vector<uint8_t>& packet) {
        if (connected_) {
            std::cout << "received packet: " << packet.size() << " bytes" << std::endl;
        }
    }
    
    bool test_server_connection(const std::string& host, int port) {
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
        
        if (sent <= 0) {
            close(sock);
            return false;
        }
        
        char buffer[64];
        ssize_t received = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        close(sock);
        
        return received > 0;
    }

private:
    VPNClient* parent_;
    bool connected_;
    std::unique_ptr<infrastructure::TunInterface> tun_interface_;
};

VPNClient::VPNClient() : impl_(std::make_unique<VPNClientImpl>(this)), status_(ConnectionStatus::DISCONNECTED) {}

VPNClient::~VPNClient() = default;

bool VPNClient::load_config(const std::string& config_file) {
    return parse_config_file(config_file);
}

std::future<bool> VPNClient::connect() {
    return impl_->connect(config_);
}

void VPNClient::disconnect() {
    impl_->disconnect();
}

bool VPNClient::is_connected() const {
    return impl_->is_connected();
}

void VPNClient::set_status_callback(StatusCallback callback) {
    status_callback_ = callback;
}

void VPNClient::set_data_callback(DataCallback callback) {
    data_callback_ = callback;
}

std::future<bool> VPNClient::send_data(const std::vector<uint8_t>& data) {
    return impl_->send_data(data);
}

ConnectionStatus VPNClient::get_status() const {
    return status_;
}

std::string VPNClient::get_last_error() const {
    return last_error_;
}

bool VPNClient::parse_config_file(const std::string& config_file) {
    try {
        if (config_file.length() >= 7 && config_file.substr(config_file.length() - 7) == ".cspvpn") {
            return parse_csp_config(config_file);
        } else if ((config_file.length() >= 5 && config_file.substr(config_file.length() - 5) == ".yaml") || (config_file.length() >= 4 && config_file.substr(config_file.length() - 4) == ".yml")) {
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

bool VPNClient::parse_csp_config(const std::string& config_file) {
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

bool VPNClient::parse_yaml_config(const std::string& config_file) {
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

void VPNClient::update_status(ConnectionStatus status, const std::string& message) {
    status_ = status;
    if (!message.empty()) {
        last_error_ = message;
    }
    if (status_callback_) {
        status_callback_(status, message);
    }
}

}
