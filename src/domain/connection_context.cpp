#include "domain/connection_context.h"
#include <sstream>
#include <random>

namespace seeded_vpn::domain {

ConnectionContext::ConnectionContext(const std::string& client_id, const ClientEndpoint& endpoint)
    : client_id_(client_id), 
      client_endpoint_(endpoint),
      session_id_(generate_session_id()),
      created_at_(std::chrono::system_clock::now()) {
}

void ConnectionContext::set_state(ConnectionState state) {
    state_ = state;
    update_activity();
}

std::string ConnectionContext::get_connection_info() const {
    std::ostringstream info;
    info << "Connection Info:\n";
    info << "  Client ID: " << client_id_ << "\n";
    info << "  Session ID: " << session_id_ << "\n";
    info << "  Endpoint: " << client_endpoint_.to_string() << "\n";
    info << "  State: " << state_to_string(state_) << "\n";
    info << "  Type: " << type_to_string(type_) << "\n";
    info << "  Assigned IP: " << (assigned_ip_.empty() ? "None" : assigned_ip_) << "\n";
    info << "  Authenticated: " << (is_authenticated_ ? "Yes" : "No") << "\n";
    info << "  Created: " << std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now() - created_at_).count() << " seconds ago\n";
    
    const auto& metrics = get_metrics();
    info << "  Session Duration: " << metrics.get_session_duration().count() << " seconds\n";
    info << "  Idle Time: " << metrics.get_idle_time().count() << " seconds\n";
    info << "  Bytes Sent: " << metrics.bytes_sent << "\n";
    info << "  Bytes Received: " << metrics.bytes_received << "\n";
    info << "  Packets Sent: " << metrics.packets_sent << "\n";
    info << "  Packets Received: " << metrics.packets_received << "\n";
    info << "  Transfer Rate: " << metrics.get_transfer_rate_mbps() << " Mbps\n";
    
    return info.str();
}

std::string ConnectionContext::get_status_summary() const {
    std::ostringstream status;
    status << client_id_ << " [" << session_id_ << "] ";
    status << state_to_string(state_) << " ";
    
    if (!assigned_ip_.empty()) {
        status << "(" << assigned_ip_ << ") ";
    }
    
    status << client_endpoint_.to_string();
    
    if (!last_error_.empty()) {
        status << " ERROR: " << last_error_;
    }
    
    return status.str();
}

bool ConnectionContext::is_valid() const {
    return !client_id_.empty() && 
           client_endpoint_.is_valid() && 
           session_id_ != 0;
}

uint32_t ConnectionContext::generate_session_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(1, 0xFFFFFFFF);
    
    return dis(gen);
}

std::string ConnectionContext::state_to_string(ConnectionState state) {
    switch (state) {
        case ConnectionState::INITIAL: return "INITIAL";
        case ConnectionState::AUTHENTICATING: return "AUTHENTICATING";
        case ConnectionState::AUTHENTICATED: return "AUTHENTICATED";
        case ConnectionState::CONNECTED: return "CONNECTED";
        case ConnectionState::DISCONNECTING: return "DISCONNECTING";
        case ConnectionState::DISCONNECTED: return "DISCONNECTED";
        case ConnectionState::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

std::string ConnectionContext::type_to_string(ConnectionType type) {
    switch (type) {
        case ConnectionType::UDP_TUNNEL: return "UDP_TUNNEL";
        case ConnectionType::HTTP_PROXY: return "HTTP_PROXY";
        case ConnectionType::DIRECT: return "DIRECT";
        default: return "UNKNOWN";
    }
}

}
