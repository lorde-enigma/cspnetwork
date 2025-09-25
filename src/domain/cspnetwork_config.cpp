#include "domain/cspnetwork_config.h"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace seeded_vpn::domain {

VPNConfig::VPNConfig(const std::string& config_file) {
    if (!load_from_file(config_file)) {
        load_defaults();
    }
}

bool VPNConfig::load_from_file(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key, value;
        
        if (!(iss >> key >> value)) continue;
        
        if (key == "server_address:") {
            server_address_ = value;
        } else if (key == "server_port:") {
            server_port_ = static_cast<uint16_t>(std::stoi(value));
        } else if (key == "protocol:") {
            protocol_ = value;
        } else if (key == "tunnel_mode:") {
            tunnel_mode_ = (value == "true");
        } else if (key == "tunnel_interface_name:") {
            tunnel_interface_name_ = value;
        } else if (key == "server_tunnel_ip:") {
            server_tunnel_ip_ = value;
        } else if (key == "ip_range:") {
            ip_range_ = value;
        } else if (key == "mtu:") {
            mtu_ = static_cast<uint16_t>(std::stoi(value));
        } else if (key == "max_connections:") {
            max_connections_ = static_cast<uint32_t>(std::stoul(value));
        } else if (key == "connection_timeout:") {
            connection_timeout_ = static_cast<uint32_t>(std::stoul(value));
        } else if (key == "log_level:") {
            log_level_ = value;
        }
    }
    
    return true;
}

void VPNConfig::load_defaults() {
    server_address_ = "0.0.0.0";
    server_port_ = 1194;
    protocol_ = "udp";
    tunnel_mode_ = true;
    tunnel_interface_name_ = "cspvpn-server";
    server_tunnel_ip_ = "10.8.0.1";
    ip_range_ = "10.8.0.0/24";
    mtu_ = 1280;
    max_connections_ = 1000;
    connection_timeout_ = 300;
    log_level_ = "info";
}

}
