#pragma once

#include <string>
#include <memory>
#include <future>
#include <functional>
#include "../domain/types.h"

namespace seeded_vpn::application {

struct ClientConfig {
    std::string server_host;
    uint16_t server_port;
    std::string client_id;
    std::string auth_token;
    std::string protocol;
    bool auto_reconnect;
    uint32_t keepalive_interval;
    uint32_t connection_timeout;
    std::string log_level;
};

enum class ConnectionStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    RECONNECTING,
    ERROR
};

class VPNClient {
public:
    using StatusCallback = std::function<void(ConnectionStatus, const std::string&)>;
    using DataCallback = std::function<void(const std::vector<uint8_t>&)>;

    VPNClient();
    ~VPNClient();

    bool load_config(const std::string& config_file);
    std::future<bool> connect();
    void disconnect();
    bool is_connected() const;
    
    void set_status_callback(StatusCallback callback);
    void set_data_callback(DataCallback callback);
    
    std::future<bool> send_data(const std::vector<uint8_t>& data);
    ConnectionStatus get_status() const;
    std::string get_last_error() const;

private:
    std::unique_ptr<class VPNClientImpl> impl_;
    ClientConfig config_;
    ConnectionStatus status_;
    std::string last_error_;
    StatusCallback status_callback_;
    DataCallback data_callback_;

    bool parse_config_file(const std::string& config_file);
    bool parse_csp_config(const std::string& config_file);
    bool parse_yaml_config(const std::string& config_file);
    void update_status(ConnectionStatus status, const std::string& message = "");
    
    friend class VPNClientImpl;
};

}
