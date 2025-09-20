#include "../include/application/vpn_client.h"
#include <iostream>
#include <fstream>
#include <regex>
#include <thread>
#include <chrono>
#include <yaml-cpp/yaml.h>

namespace seeded_vpn::application {

class VPNClientImpl {
public:
    VPNClientImpl(VPNClient* parent) : parent_(parent), connected_(false) {}
    
    std::future<bool> connect(const ClientConfig& config) {
        auto promise = std::make_shared<std::promise<bool>>();
        auto future = promise->get_future();
        
        std::thread([this, config, promise]() {
            parent_->update_status(ConnectionStatus::CONNECTING, "connecting to " + config.server_host);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            parent_->update_status(ConnectionStatus::CONNECTING, "authenticating");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            connected_ = true;
            parent_->update_status(ConnectionStatus::CONNECTED, "connected successfully");
            promise->set_value(true);
        }).detach();
        
        return future;
    }
    
    void disconnect() {
        connected_ = false;
        parent_->update_status(ConnectionStatus::DISCONNECTED, "disconnected");
    }
    
    bool is_connected() const {
        return connected_;
    }
    
    std::future<bool> send_data(const std::vector<uint8_t>& data) {
        auto promise = std::make_shared<std::promise<bool>>();
        auto future = promise->get_future();
        promise->set_value(connected_);
        return future;
    }

private:
    VPNClient* parent_;
    bool connected_;
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
        if (config_file.ends_with(".cspvpn")) {
            return parse_csp_config(config_file);
        } else if (config_file.ends_with(".yaml") || config_file.ends_with(".yml")) {
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
        
        if (line.starts_with("remote ")) {
            std::istringstream iss(line);
            std::string keyword, host;
            uint16_t port;
            if (iss >> keyword >> host >> port) {
                config_.server_host = host;
                config_.server_port = port;
            }
        } else if (line.starts_with("auth-user-pass")) {
            std::istringstream iss(line);
            std::string keyword, auth_file;
            if (iss >> keyword >> auth_file) {
                std::ifstream auth(auth_file);
                if (auth.is_open()) {
                    std::getline(auth, config_.client_id);
                    std::getline(auth, config_.auth_token);
                }
            }
        } else if (line.starts_with("proto ")) {
            std::istringstream iss(line);
            std::string keyword, protocol;
            if (iss >> keyword >> protocol) {
                config_.protocol = protocol;
            }
        } else if (line.starts_with("keepalive ")) {
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
