#pragma once

#include <string>
#include <cstdint>

namespace seeded_vpn::domain {

class VPNConfig {
public:
    VPNConfig() = default;
    explicit VPNConfig(const std::string& config_file);
    
    bool load_from_file(const std::string& config_file);
    void load_defaults();
    
    // Server configuration
    std::string get_server_address() const { return server_address_; }
    uint16_t get_server_port() const { return server_port_; }
    std::string get_protocol() const { return protocol_; }
    bool get_tunnel_mode() const { return tunnel_mode_; }
    
    // Network configuration
    std::string get_tunnel_interface_name() const { return tunnel_interface_name_; }
    std::string get_server_tunnel_ip() const { return server_tunnel_ip_; }
    std::string get_ip_range() const { return ip_range_; }
    uint16_t get_mtu() const { return mtu_; }
    
    // Security configuration
    uint32_t get_max_connections() const { return max_connections_; }
    uint32_t get_connection_timeout() const { return connection_timeout_; }
    
    // Logging
    std::string get_log_level() const { return log_level_; }
    
    // Setters for testing
    void set_server_address(const std::string& address) { server_address_ = address; }
    void set_server_port(uint16_t port) { server_port_ = port; }
    void set_tunnel_mode(bool enabled) { tunnel_mode_ = enabled; }
    void set_ip_range(const std::string& range) { ip_range_ = range; }
    
private:
    // Server settings
    std::string server_address_ = "0.0.0.0";
    uint16_t server_port_ = 1194;
    std::string protocol_ = "udp";
    bool tunnel_mode_ = true;
    
    // Network settings
    std::string tunnel_interface_name_ = "cspvpn-server";
    std::string server_tunnel_ip_ = "10.8.0.1";
    std::string ip_range_ = "10.8.0.0/24";
    uint16_t mtu_ = 1280;
    
    // Security settings
    uint32_t max_connections_ = 1000;
    uint32_t connection_timeout_ = 300;
    
    // Logging
    std::string log_level_ = "info";
};

}
