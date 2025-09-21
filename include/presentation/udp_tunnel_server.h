#pragma once

#include <memory>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <vector>
#include <functional>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../infrastructure/tun_interface.h"
#include "../protocol/udp_tunnel_protocol.h"
#include "../infrastructure/ip_pool.h"
#include "../domain/connection_context.h"
#include "../domain/vpn_config.h"

namespace seeded_vpn::presentation {

struct ClientSession {
    std::string client_id;
    sockaddr_in6 client_address;
    std::string allocated_ip;
    std::chrono::steady_clock::time_point last_activity;
    protocol::SessionState state;
    uint32_t session_id;
    
    bool is_expired(std::chrono::seconds timeout) const {
        return std::chrono::steady_clock::now() - last_activity > timeout;
    }
    
    void update_activity() {
        last_activity = std::chrono::steady_clock::now();
    }
};

class UDPTunnelServer {
public:
    explicit UDPTunnelServer(std::shared_ptr<domain::VPNConfig> config);
    ~UDPTunnelServer();
    
    bool start();
    void stop();
    bool is_running() const;
    
    void set_config_path(const std::string& config_path);
    void set_max_clients(size_t max_clients);
    void set_session_timeout(std::chrono::seconds timeout);
    
    size_t get_active_clients_count() const;
    std::vector<ClientSession> get_active_sessions() const;

private:
    void server_loop();
    void tun_packet_loop();
    void cleanup_expired_sessions();
    
    void handle_udp_packet(const std::vector<uint8_t>& packet, const sockaddr_in6& client_addr);
    void handle_auth_packet(const protocol::TunnelPacket& tunnel_packet, const sockaddr_in6& client_addr);
    void handle_data_packet(const protocol::TunnelPacket& tunnel_packet, const sockaddr_in6& client_addr);
    void handle_keepalive_packet(const protocol::TunnelPacket& tunnel_packet, const sockaddr_in6& client_addr);
    void handle_disconnect_packet(const protocol::TunnelPacket& tunnel_packet, const sockaddr_in6& client_addr);
    
    void relay_tun_to_clients(const std::vector<uint8_t>& ip_packet);
    void relay_to_client(const std::string& client_id, const std::vector<uint8_t>& ip_packet);
    void broadcast_to_all_clients(const std::vector<uint8_t>& ip_packet);
    
    bool authenticate_client(const std::string& client_id, const std::string& auth_data);
    bool allocate_client_ip(const std::string& client_id, std::string& allocated_ip);
    void deallocate_client_ip(const std::string& client_id);
    
    std::string generate_session_id();
    std::string extract_destination_ip(const std::vector<uint8_t>& ip_packet);
    std::string find_client_by_ip(const std::string& destination_ip);
    
    void send_auth_response(const sockaddr_in6& client_addr, bool success, const std::string& allocated_ip);
    void send_udp_packet(const sockaddr_in6& client_addr, const std::vector<uint8_t>& packet);
    
    void setup_server_tun();
    void configure_server_routing();
    void enable_ip_forwarding();
    
    uint16_t port_;
    int udp_socket_;
    std::atomic<bool> running_;
    
    std::shared_ptr<domain::VPNConfig> config_;
    std::unique_ptr<infrastructure::TunInterface> server_tun_;
    std::unique_ptr<infrastructure::IPPool> ip_pool_;
    
    std::unordered_map<std::string, ClientSession> active_clients_;
    std::unordered_map<std::string, std::string> ip_to_client_map_;
    
    mutable std::mutex clients_mutex_;
    std::thread server_thread_;
    std::thread tun_thread_;
    std::thread cleanup_thread_;
    
    std::string config_path_;
    size_t max_clients_;
    std::chrono::seconds session_timeout_;
    
    std::function<void(const std::string&)> logger_;
};

}
