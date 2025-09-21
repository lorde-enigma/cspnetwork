#pragma once

#include <string>
#include <chrono>
#include <memory>
#include <atomic>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace seeded_vpn::domain {

enum class ConnectionState {
    INITIAL,
    AUTHENTICATING,
    AUTHENTICATED,
    CONNECTED,
    DISCONNECTING,
    DISCONNECTED,
    ERROR
};

enum class ConnectionType {
    UDP_TUNNEL,
    HTTP_PROXY,
    DIRECT
};

struct ClientEndpoint {
    std::string ip_address;
    uint16_t port;
    sockaddr_in sockaddr;
    
    ClientEndpoint() : port(0) {
        sockaddr = {};
    }
    
    ClientEndpoint(const std::string& ip, uint16_t p) : ip_address(ip), port(p) {
        sockaddr = {};
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port = htons(port);
        inet_pton(AF_INET, ip_address.c_str(), &sockaddr.sin_addr);
    }
    
    std::string to_string() const {
        return ip_address + ":" + std::to_string(port);
    }
    
    bool is_valid() const {
        return !ip_address.empty() && port > 0;
    }
};

struct SessionMetrics {
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> packets_dropped{0};
    std::chrono::system_clock::time_point session_start;
    std::chrono::system_clock::time_point last_activity;
    
    SessionMetrics() {
        auto now = std::chrono::system_clock::now();
        session_start = now;
        last_activity = now;
    }
    
    void update_activity() {
        last_activity = std::chrono::system_clock::now();
    }
    
    std::chrono::duration<double> get_session_duration() const {
        return std::chrono::system_clock::now() - session_start;
    }
    
    std::chrono::duration<double> get_idle_time() const {
        return std::chrono::system_clock::now() - last_activity;
    }
    
    double get_transfer_rate_mbps() const {
        auto duration = get_session_duration().count();
        if (duration <= 0) return 0.0;
        return ((bytes_sent + bytes_received) * 8.0) / (duration * 1000000.0);
    }
};

class ConnectionContext {
public:
    ConnectionContext(const std::string& client_id, const ClientEndpoint& endpoint);
    
    ~ConnectionContext() = default;
    
    // Basic properties
    const std::string& get_client_id() const { return client_id_; }
    const ClientEndpoint& get_client_endpoint() const { return client_endpoint_; }
    uint32_t get_session_id() const { return session_id_; }
    ConnectionState get_state() const { return state_; }
    ConnectionType get_type() const { return type_; }
    
    // IP assignment
    void set_assigned_ip(const std::string& ip) { assigned_ip_ = ip; }
    const std::string& get_assigned_ip() const { return assigned_ip_; }
    bool has_assigned_ip() const { return !assigned_ip_.empty(); }
    
    // State management
    void set_state(ConnectionState state);
    bool is_connected() const { return state_ == ConnectionState::CONNECTED; }
    bool is_active() const { 
        return state_ == ConnectionState::CONNECTED || 
               state_ == ConnectionState::AUTHENTICATED || 
               state_ == ConnectionState::AUTHENTICATING; 
    }
    
    // Connection type
    void set_type(ConnectionType type) { type_ = type; }
    
    // Authentication
    void set_authenticated(bool auth) { is_authenticated_ = auth; }
    bool is_authenticated() const { return is_authenticated_; }
    void set_auth_token(const std::string& token) { auth_token_ = token; }
    const std::string& get_auth_token() const { return auth_token_; }
    
    // Metrics
    SessionMetrics& get_metrics() { return metrics_; }
    const SessionMetrics& get_metrics() const { return metrics_; }
    void update_activity() { metrics_.update_activity(); }
    
    // Sequence numbers
    uint32_t get_next_sequence() { return ++last_sequence_number_; }
    uint32_t get_last_sequence() const { return last_sequence_number_; }
    void set_last_received_sequence(uint32_t seq) { last_received_sequence_ = seq; }
    uint32_t get_last_received_sequence() const { return last_received_sequence_; }
    
    // Timing
    std::chrono::system_clock::time_point get_created_at() const { return created_at_; }
    std::chrono::system_clock::time_point get_last_activity() const { return metrics_.last_activity; }
    bool is_idle(std::chrono::seconds timeout) const {
        return metrics_.get_idle_time() > timeout;
    }
    
    // Error handling
    void set_error(const std::string& error) { last_error_ = error; }
    const std::string& get_last_error() const { return last_error_; }
    bool has_error() const { return !last_error_.empty(); }
    
    // Connection info
    std::string get_connection_info() const;
    std::string get_status_summary() const;
    
    // Validation
    bool is_valid() const;
    
private:
    const std::string client_id_;
    const ClientEndpoint client_endpoint_;
    const uint32_t session_id_;
    const std::chrono::system_clock::time_point created_at_;
    
    std::atomic<ConnectionState> state_{ConnectionState::INITIAL};
    ConnectionType type_{ConnectionType::UDP_TUNNEL};
    std::string assigned_ip_;
    std::atomic<bool> is_authenticated_{false};
    std::string auth_token_;
    
    std::atomic<uint32_t> last_sequence_number_{0};
    std::atomic<uint32_t> last_received_sequence_{0};
    
    SessionMetrics metrics_;
    std::string last_error_;
    
    static uint32_t generate_session_id();
    static std::string state_to_string(ConnectionState state);
    static std::string type_to_string(ConnectionType type);
};

}
