#include "presentation/udp_tunnel_server.h"
#include "infrastructure/tun_interface.h"
#include "protocol/udp_tunnel_protocol.h"
#include "domain/cspnetwork_config.h"
#include "infrastructure/ip_pool.h"
#include "domain/connection_context.h"
#include "infrastructure/logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <cstring>

using namespace seeded_vpn;

namespace seeded_vpn {
namespace presentation {

UDPTunnelServer::UDPTunnelServer(std::shared_ptr<domain::VPNConfig> config)
    : config_(config), running_(false), udp_socket_(-1),
      max_clients_(100), session_timeout_(std::chrono::seconds(300)) {
    
    port_ = 8080;
    ip_pool_ = std::make_unique<infrastructure::IPPool>("10.8.0.0/24");
    
    logger_ = [](const std::string& msg) {
        std::cout << "[INFO] " << msg << std::endl;
    };
}

UDPTunnelServer::~UDPTunnelServer() {
    stop();
}

bool seeded_vpn::presentation::UDPTunnelServer::start() {
    if (running_) return false;
    
    try {
        setup_server_tun();
        
        udp_socket_ = socket(AF_INET6, SOCK_DGRAM, 0);
        if (udp_socket_ < 0) {
            throw std::runtime_error("failed to create socket");
        }
        
        int opt = 0;
        if (setsockopt(udp_socket_, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
            close(udp_socket_);
            throw std::runtime_error("failed to set socket option");
        }
        
        sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(port_);
        
        if (bind(udp_socket_, (sockaddr*)&addr, sizeof(addr)) < 0) {
            close(udp_socket_);
            throw std::runtime_error("failed to bind socket");
        }
        
        running_ = true;
        
        server_thread_ = std::thread(&UDPTunnelServer::server_loop, this);
        tun_thread_ = std::thread(&UDPTunnelServer::tun_packet_loop, this);
        cleanup_thread_ = std::thread(&UDPTunnelServer::cleanup_expired_sessions, this);
        
        logger_("udp tunnel server started on port " + std::to_string(port_));
        return true;
        
    } catch (const std::exception& e) {
        logger_("failed to start server: " + std::string(e.what()));
        stop();
        return false;
    }
}

void seeded_vpn::presentation::UDPTunnelServer::stop() {
    if (!running_) return;
    
    running_ = false;
    
    if (udp_socket_ != -1) {
        close(udp_socket_);
        udp_socket_ = -1;
    }
    
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    
    if (tun_thread_.joinable()) {
        tun_thread_.join();
    }
    
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
    
    logger_("udp tunnel server stopped");
}

bool seeded_vpn::presentation::UDPTunnelServer::is_running() const {
    return running_;
}

void seeded_vpn::presentation::UDPTunnelServer::set_config_path(const std::string& config_path) {
    config_path_ = config_path;
}

void seeded_vpn::presentation::UDPTunnelServer::set_max_clients(size_t max_clients) {
    max_clients_ = max_clients;
}

void seeded_vpn::presentation::UDPTunnelServer::set_session_timeout(std::chrono::seconds timeout) {
    session_timeout_ = timeout;
}

size_t UDPTunnelServer::get_active_clients_count() const {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    return active_clients_.size();
}

std::vector<ClientSession> UDPTunnelServer::get_active_sessions() const {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    std::vector<ClientSession> sessions;
    for (const auto& [id, session] : active_clients_) {
        sessions.push_back(session);
    }
    return sessions;
}

void seeded_vpn::presentation::UDPTunnelServer::server_loop() {
    char buffer[4096];
    sockaddr_in6 client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    while (running_) {
        ssize_t received = recvfrom(udp_socket_, buffer, sizeof(buffer), 0,
                                  (sockaddr*)&client_addr, &addr_len);
        
        if (received > 0) {
            std::vector<uint8_t> packet(buffer, buffer + received);
            handle_udp_packet(packet, client_addr);
        }
    }
}

void seeded_vpn::presentation::UDPTunnelServer::tun_packet_loop() {
    char buffer[4096];
    
    while (running_ && server_tun_) {
        ssize_t received = read(server_tun_->get_fd(), buffer, sizeof(buffer));
        if (received > 0) {
            std::vector<uint8_t> packet(buffer, buffer + received);
            relay_tun_to_clients(packet);
        }
    }
}

void seeded_vpn::presentation::UDPTunnelServer::cleanup_expired_sessions() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(60));
        
        std::lock_guard<std::mutex> lock(clients_mutex_);
        auto it = active_clients_.begin();
        while (it != active_clients_.end()) {
            if (it->second.is_expired(session_timeout_)) {
                ip_to_client_map_.erase(it->second.allocated_ip);
                deallocate_client_ip(it->first);
                it = active_clients_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void seeded_vpn::presentation::UDPTunnelServer::handle_udp_packet(const std::vector<uint8_t>& packet, const sockaddr_in6& client_addr) {
    auto tunnel_packet = protocol::TunnelPacket::deserialize(packet);
    if (!tunnel_packet || !tunnel_packet->is_valid()) return;
    
    switch (tunnel_packet->get_type()) {
        case protocol::PacketType::AUTH_REQUEST:
            handle_auth_packet(*tunnel_packet, client_addr);
            break;
            
        case protocol::PacketType::DATA:
            handle_data_packet(*tunnel_packet, client_addr);
            break;
            
        case protocol::PacketType::KEEPALIVE:
            handle_keepalive_packet(*tunnel_packet, client_addr);
            break;
            
        case protocol::PacketType::DISCONNECT:
            handle_disconnect_packet(*tunnel_packet, client_addr);
            break;
            
        case protocol::PacketType::AUTH_RESPONSE:
        case protocol::PacketType::ERROR_RESPONSE:
            break;
    }
}

void seeded_vpn::presentation::UDPTunnelServer::handle_auth_packet(const protocol::TunnelPacket& tunnel_packet, const sockaddr_in6& client_addr) {
    auto auth_req = protocol::AuthRequest::parse(tunnel_packet.get_payload());
    
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &client_addr.sin6_addr, ip_str, sizeof(ip_str));
    std::string client_key = std::string(ip_str) + ":" + std::to_string(ntohs(client_addr.sin6_port));
    
    if (!authenticate_client(auth_req.client_id, auth_req.auth_token)) {
        auto error_response = protocol::TunnelPacket::create_error_response("authentication failed");
        auto serialized_response = error_response->serialize();
        send_udp_packet(client_addr, serialized_response);
        return;
    }
    
    std::string allocated_ip;
    if (allocate_client_ip(client_key, allocated_ip)) {
        ClientSession session;
        session.client_id = auth_req.client_id;
        session.client_address = client_addr;
        session.allocated_ip = allocated_ip;
        session.state = protocol::SessionState::CONNECTED;
        session.session_id = std::stoul(generate_session_id());
        session.update_activity();
        
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            active_clients_[client_key] = session;
            ip_to_client_map_[allocated_ip] = client_key;
        }
        
        auto auth_response = protocol::TunnelPacket::create_auth_response(session.session_id, protocol::AuthResult::SUCCESS, allocated_ip);
        auto serialized_response = auth_response->serialize();
        send_udp_packet(client_addr, serialized_response);
        logger_("client authenticated: " + auth_req.client_id + " -> " + allocated_ip);
    } else {
        auto auth_response = protocol::TunnelPacket::create_auth_response(0, protocol::AuthResult::IP_ALLOCATION_FAILED);
        auto serialized_response = auth_response->serialize();
        send_udp_packet(client_addr, serialized_response);
    }
}

void seeded_vpn::presentation::UDPTunnelServer::handle_data_packet(const protocol::TunnelPacket& tunnel_packet, const sockaddr_in6& client_addr) {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &client_addr.sin6_addr, ip_str, sizeof(ip_str));
    std::string client_id = std::string(ip_str) + ":" + std::to_string(ntohs(client_addr.sin6_port));
    
    std::lock_guard<std::mutex> lock(clients_mutex_);
    auto it = active_clients_.find(client_id);
    if (it != active_clients_.end()) {
        it->second.update_activity();
        
        const auto& payload = tunnel_packet.get_payload();
        write(server_tun_->get_fd(), payload.data(), payload.size());
    }
}

void seeded_vpn::presentation::UDPTunnelServer::handle_keepalive_packet(const protocol::TunnelPacket& tunnel_packet, const sockaddr_in6& client_addr) {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &client_addr.sin6_addr, ip_str, sizeof(ip_str));
    std::string client_key = std::string(ip_str) + ":" + std::to_string(ntohs(client_addr.sin6_port));
    
    std::lock_guard<std::mutex> lock(clients_mutex_);
    auto it = active_clients_.find(client_key);
    if (it != active_clients_.end()) {
        it->second.update_activity();
        
        auto keepalive_response = protocol::TunnelPacket::create_keepalive(tunnel_packet.get_session_id());
        auto serialized_response = keepalive_response->serialize();
        send_udp_packet(client_addr, serialized_response);
    }
}

void seeded_vpn::presentation::UDPTunnelServer::handle_disconnect_packet(const protocol::TunnelPacket& tunnel_packet, const sockaddr_in6& client_addr) {
    (void)tunnel_packet; // Packet validation would be done in real implementation
    
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &client_addr.sin6_addr, ip_str, sizeof(ip_str));
    std::string client_key = std::string(ip_str) + ":" + std::to_string(ntohs(client_addr.sin6_port));
    
    std::lock_guard<std::mutex> lock(clients_mutex_);
    auto it = active_clients_.find(client_key);
    if (it != active_clients_.end()) {
        std::string allocated_ip = it->second.allocated_ip;
        std::string client_name = it->second.client_id;
        
        ip_pool_->release_ip(allocated_ip);
        ip_to_client_map_.erase(allocated_ip);
        active_clients_.erase(it);
        
        logger_("client disconnected: " + client_name + " (released " + allocated_ip + ")");
    }
}

void seeded_vpn::presentation::UDPTunnelServer::relay_tun_to_clients(const std::vector<uint8_t>& ip_packet) {
    std::string dest_ip = extract_destination_ip(ip_packet);
    std::string client_id = find_client_by_ip(dest_ip);
    
    if (!client_id.empty()) {
        relay_to_client(client_id, ip_packet);
    } else {
        broadcast_to_all_clients(ip_packet);
    }
}

void seeded_vpn::presentation::UDPTunnelServer::relay_to_client(const std::string& client_id, const std::vector<uint8_t>& ip_packet) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    auto it = active_clients_.find(client_id);
    if (it != active_clients_.end()) {
        auto packet = protocol::TunnelPacket::create_data_packet(it->second.session_id, ip_packet);
        if (packet) {
            auto serialized = packet->serialize();
            send_udp_packet(it->second.client_address, serialized);
        }
    }
}

void seeded_vpn::presentation::UDPTunnelServer::broadcast_to_all_clients(const std::vector<uint8_t>& ip_packet) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    for (const auto& [id, session] : active_clients_) {
        relay_to_client(id, ip_packet);
    }
}

bool seeded_vpn::presentation::UDPTunnelServer::authenticate_client(const std::string& client_id, const std::string& auth_token) {
    if (client_id.empty() || auth_token.empty()) {
        logger_("authentication failed: empty credentials");
        return false;
    }
    
    if (auth_token != "token123") {
        logger_("authentication failed for client: " + client_id);
        return false;
    }
    
    logger_("client authenticated successfully: " + client_id);
    return true;
}

bool seeded_vpn::presentation::UDPTunnelServer::allocate_client_ip(const std::string& client_id, std::string& allocated_ip) {
    auto result = ip_pool_->allocate_ip(client_id);
    if (result.has_value()) {
        allocated_ip = result.value();
        return true;
    }
    return false;
}

void seeded_vpn::presentation::UDPTunnelServer::deallocate_client_ip(const std::string& client_id) {
    ip_pool_->release_ip(client_id);
}

std::string seeded_vpn::presentation::UDPTunnelServer::generate_session_id() {
    static uint32_t counter = 1;
    return std::to_string(counter++);
}

std::string seeded_vpn::presentation::UDPTunnelServer::extract_destination_ip(const std::vector<uint8_t>& ip_packet) {
    if (ip_packet.size() < 20) return "";
    
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_packet[16], dest_ip, sizeof(dest_ip));
    return std::string(dest_ip);
}

std::string seeded_vpn::presentation::UDPTunnelServer::find_client_by_ip(const std::string& destination_ip) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    auto it = ip_to_client_map_.find(destination_ip);
    return (it != ip_to_client_map_.end()) ? it->second : "";
}

void seeded_vpn::presentation::UDPTunnelServer::send_auth_response(const sockaddr_in6& client_addr, bool success, const std::string& allocated_ip) {
    auto response = success ? 
        protocol::TunnelPacket::create_auth_response(0, protocol::AuthResult::SUCCESS, allocated_ip) :
        protocol::TunnelPacket::create_auth_response(0, protocol::AuthResult::IP_ALLOCATION_FAILED);
    
    if (response) {
        auto serialized = response->serialize();
        send_udp_packet(client_addr, serialized);
    }
}

void seeded_vpn::presentation::UDPTunnelServer::send_udp_packet(const sockaddr_in6& client_addr, const std::vector<uint8_t>& packet) {
    sendto(udp_socket_, packet.data(), packet.size(), 0,
           (sockaddr*)&client_addr, sizeof(client_addr));
}

void seeded_vpn::presentation::UDPTunnelServer::setup_server_tun() {
    server_tun_ = std::make_unique<infrastructure::TunInterface>();
    
    infrastructure::TunConfig config;
    config.device_name = "vpn_tun0";
    config.local_ip = "10.8.0.1";
    config.remote_ip = "10.8.0.2";
    config.netmask = "255.255.255.0";
    config.mtu = 1500;
    config.persistent = false;
    
    if (!server_tun_->create_tun(config)) {
        throw std::runtime_error("failed to create tun interface");
    }
    configure_server_routing();
}

void seeded_vpn::presentation::UDPTunnelServer::configure_server_routing() {
    enable_ip_forwarding();
}

void seeded_vpn::presentation::UDPTunnelServer::enable_ip_forwarding() {
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
}

}
}
