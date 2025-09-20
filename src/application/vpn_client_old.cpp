#include "../include/application/vpn_client.h"
#include "../include/infrastructure/config_manager.h"
#include "../include/infrastructure/error_handler.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>
#include <regex>
#include <future>
#include <asio.hpp>
#include <yaml-cpp/yaml.h>

namespace seeded_vpn::application {

class VPNClientImpl {
public:
    VPNClientImpl(VPNClient* parent) : parent_(parent), socket_(io_context_) {}
    
    ~VPNClientImpl() {
        disconnect();
    }

    std::future<bool> connect(const ClientConfig& config) {
        auto promise = std::make_shared<std::promise<bool>>();
        auto future = promise->get_future();

        config_ = config;
        
        std::thread([this, promise]() {
            try {
                parent_->update_status(ConnectionStatus::CONNECTING, "resolving server address");
                
                asio::ip::tcp::resolver resolver(io_context_);
                auto endpoints = resolver.resolve(config_.server_host, std::to_string(config_.server_port));
                
                parent_->update_status(ConnectionStatus::CONNECTING, "establishing connection");
                
                asio::async_connect(socket_, endpoints,
                    [this, promise](std::error_code ec, asio::ip::tcp::endpoint) {
                        if (!ec) {
                            parent_->update_status(ConnectionStatus::CONNECTING, "authenticating");
                            send_auth_request(promise);
                        } else {
                            parent_->update_status(ConnectionStatus::ERROR, "connection failed: " + ec.message());
                            promise->set_value(false);
                        }
                    });
                
                io_thread_ = std::thread([this]() { io_context_.run(); });
                
            } catch (const std::exception& e) {
                parent_->update_status(ConnectionStatus::ERROR, std::string("connection error: ") + e.what());
                promise->set_value(false);
            }
        }).detach();

        return future;
    }

    void disconnect() {
        if (socket_.is_open()) {
            socket_.close();
        }
        io_context_.stop();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
        io_context_.restart();
    }

    bool is_connected() const {
        return socket_.is_open();
    }

    std::future<bool> send_data(const std::vector<uint8_t>& data) {
        auto promise = std::make_shared<std::promise<bool>>();
        auto future = promise->get_future();

        if (!socket_.is_open()) {
            promise->set_value(false);
            return future;
        }

        asio::async_write(socket_, asio::buffer(data),
            [promise](std::error_code ec, std::size_t) {
                promise->set_value(!ec);
            });

        return future;
    }

private:
    VPNClient* parent_;
    ClientConfig config_;
    asio::io_context io_context_;
    asio::ip::tcp::socket socket_;
    std::thread io_thread_;

    void send_auth_request(std::shared_ptr<std::promise<bool>> promise) {
        std::string auth_data = R"({"type":"auth","client_id":")" + config_.client_id + 
                               R"(","token":")" + config_.auth_token + R"("})";
        
        auto buffer = std::make_shared<std::string>(auth_data);
        asio::async_write(socket_, asio::buffer(*buffer),
            [this, promise, buffer](std::error_code ec, std::size_t) {
                if (!ec) {
                    wait_for_auth_response(promise);
                } else {
                    parent_->update_status(ConnectionStatus::ERROR, "authentication failed");
                    promise->set_value(false);
                }
            });
    }

    void wait_for_auth_response(std::shared_ptr<std::promise<bool>> promise) {
        auto buffer = std::make_shared<std::vector<uint8_t>>(1024);
        
        socket_.async_read_some(asio::buffer(*buffer),
            [this, promise, buffer](std::error_code ec, std::size_t bytes_transferred) {
                if (!ec && bytes_transferred > 0) {
                    std::string response(buffer->begin(), buffer->begin() + bytes_transferred);
                    
                    if (response.find("\"status\":\"success\"") != std::string::npos) {
                        parent_->update_status(ConnectionStatus::CONNECTED, "connected successfully");
                        start_data_loop();
                        promise->set_value(true);
                    } else {
                        parent_->update_status(ConnectionStatus::ERROR, "authentication rejected");
                        promise->set_value(false);
                    }
                } else {
                    parent_->update_status(ConnectionStatus::ERROR, "authentication timeout");
                    promise->set_value(false);
                }
            });
    }

    void start_data_loop() {
        read_data();
        start_keepalive();
    }

    void read_data() {
        auto buffer = std::make_shared<std::vector<uint8_t>>(4096);
        
        socket_.async_read_some(asio::buffer(*buffer),
            [this, buffer](std::error_code ec, std::size_t bytes_transferred) {
                if (!ec && bytes_transferred > 0) {
                    std::vector<uint8_t> data(buffer->begin(), buffer->begin() + bytes_transferred);
                    if (parent_->data_callback_) {
                        parent_->data_callback_(data);
                    }
                    read_data();
                } else if (ec != asio::error::operation_aborted) {
                    parent_->update_status(ConnectionStatus::ERROR, "connection lost: " + ec.message());
                }
            });
    }

    void start_keepalive() {
        auto timer = std::make_shared<asio::steady_timer>(io_context_, 
                                                         std::chrono::seconds(config_.keepalive_interval));
        
        timer->async_wait([this, timer](std::error_code ec) {
            if (!ec && socket_.is_open()) {
                std::string keepalive = R"({"type":"keepalive"})";
                asio::async_write(socket_, asio::buffer(keepalive),
                    [this, timer](std::error_code ec, std::size_t) {
                        if (!ec) {
                            start_keepalive();
                        }
                    });
            }
        });
    }
};

VPNClient::VPNClient() 
    : impl_(std::make_unique<VPNClientImpl>(this))
    , status_(ConnectionStatus::DISCONNECTED) {
}

VPNClient::~VPNClient() = default;

bool VPNClient::load_config(const std::string& config_file) {
    return parse_config_file(config_file);
}

std::future<bool> VPNClient::connect() {
    if (status_ == ConnectionStatus::CONNECTED) {
        auto promise = std::promise<bool>();
        promise.set_value(true);
        return promise.get_future();
    }

    return impl_->connect(config_);
}

void VPNClient::disconnect() {
    impl_->disconnect();
    update_status(ConnectionStatus::DISCONNECTED, "disconnected");
}

bool VPNClient::is_connected() const {
    return status_ == ConnectionStatus::CONNECTED;
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
    while (std::getline(file, line)) {
        line = std::regex_replace(line, std::regex("^\\s+|\\s+$"), "");
        
        if (line.empty() || line[0] == '#') continue;

        size_t pos = line.find(' ');
        if (pos == std::string::npos) continue;

        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);

        if (key == "remote") {
            size_t space_pos = value.find(' ');
            if (space_pos != std::string::npos) {
                config_.server_host = value.substr(0, space_pos);
                config_.server_port = static_cast<uint16_t>(std::stoi(value.substr(space_pos + 1)));
            } else {
                config_.server_host = value;
                config_.server_port = 8080;
            }
        } else if (key == "client-id") {
            config_.client_id = value;
        } else if (key == "auth-token") {
            config_.auth_token = value;
        } else if (key == "protocol") {
            config_.protocol = value;
        } else if (key == "keepalive") {
            config_.keepalive_interval = static_cast<uint32_t>(std::stoi(value));
        } else if (key == "connect-timeout") {
            config_.connection_timeout = static_cast<uint32_t>(std::stoi(value));
        } else if (key == "log-level") {
            config_.log_level = value;
        } else if (key == "auto-reconnect") {
            config_.auto_reconnect = (value == "true" || value == "1");
        }
    }

    if (config_.server_host.empty()) {
        last_error_ = "server host not specified in config";
        return false;
    }

    if (config_.client_id.empty()) {
        config_.client_id = "client_" + std::to_string(std::time(nullptr));
    }

    if (config_.keepalive_interval == 0) {
        config_.keepalive_interval = 30;
    }

    if (config_.connection_timeout == 0) {
        config_.connection_timeout = 10;
    }

    return true;
}

bool VPNClient::parse_yaml_config(const std::string& config_file) {
    try {
        YAML::Node yaml = YAML::LoadFile(config_file);
        
        if (yaml["server"]) {
            auto server = yaml["server"];
            config_.server_host = server["host"].as<std::string>("");
            config_.server_port = server["port"].as<uint16_t>(8080);
        }

        config_.client_id = yaml["client_id"].as<std::string>("client_" + std::to_string(std::time(nullptr)));
        config_.auth_token = yaml["auth_token"].as<std::string>("");
        config_.protocol = yaml["protocol"].as<std::string>("tcp");
        config_.auto_reconnect = yaml["auto_reconnect"].as<bool>(true);
        config_.keepalive_interval = yaml["keepalive_interval"].as<uint32_t>(30);
        config_.connection_timeout = yaml["connection_timeout"].as<uint32_t>(10);
        config_.log_level = yaml["log_level"].as<std::string>("info");

        return !config_.server_host.empty();
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
