#include "presentation/udp_tunnel_server.h"
#include "infrastructure/logger.h"
#include "infrastructure/tun_interface.h"
#include "infrastructure/ip_pool.h"
#include "protocol/udp_tunnel_protocol.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <chrono>
#include <random>

namespace seeded_vpn::presentation {

UDPTunnelServer::UDPTunnelServer(std::shared_ptr<domain::VPNConfig> config)
    : config_(config)
    , port_(config->get_server_port())
    , udp_socket_(-1)
    , running_(false)
    , max_clients_(100)
    , session_timeout_(std::chrono::seconds(300))
{
    server_tun_ = std::make_unique<infrastructure::TunInterface>();
    ip_pool_ = std::make_unique<infrastructure::IPPool>(config->get_ip_range());
    
    logger_ = [](const std::string& msg) {
        ::infrastructure::Logger::getInstance().info(msg);
    };
}

UDPTunnelServer::~UDPTunnelServer() {
    stop();
}

bool UDPTunnelServer::start() {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    if (running_.load()) {
        logger_("server already running");
        return false;
    }
    
    udp_socket_ = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udp_socket_ < 0) {
        logger_("failed to create udp socket");
        return false;
    }
    
    sockaddr_in6 server_addr{};
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(port_);
    
    int dual_stack = 0;
    if (setsockopt(udp_socket_, IPPROTO_IPV6, IPV6_V6ONLY, &dual_stack, sizeof(dual_stack)) < 0) {
        logger_("failed to set dual stack mode");
        close(udp_socket_);
        return false;
    }
    
    if (bind(udp_socket_, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        logger_("failed to bind udp socket to port " + std::to_string(port_));
        close(udp_socket_);
        return false;
    }
    
    setup_server_tun();
    
    running_.store(true);
    
    server_thread_ = std::thread(&UDPTunnelServer::server_loop, this);
    tun_thread_ = std::thread(&UDPTunnelServer::tun_packet_loop, this);
    cleanup_thread_ = std::thread(&UDPTunnelServer::cleanup_expired_sessions, this);
    
    logger_("udp tunnel server started on port " + std::to_string(port_));
    return true;
}

void UDPTunnelServer::stop() {
    if (!running_.load()) {
        return;
    }
    
    running_.store(false);
    
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    
    if (tun_thread_.joinable()) {
        tun_thread_.join();
    }
    
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
    
    if (udp_socket_ >= 0) {
        close(udp_socket_);
        udp_socket_ = -1;
    }
    
    server_tun_->destroy_tun();
    
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        for (auto& [client_id, client] : active_clients_) {
            deallocate_client_ip(client_id);
        }
        active_clients_.clear();
        ip_to_client_map_.clear();
    }
    
    logger_("udp tunnel server stopped");
}

bool UDPTunnelServer::is_running() const {
    return running_.load();
}

void UDPTunnelServer::set_config_path(const std::string& config_path) {
    config_path_ = config_path;
}

void UDPTunnelServer::set_max_clients(size_t max_clients) {
    max_clients_ = max_clients;
}

void UDPTunnelServer::set_session_timeout(std::chrono::seconds timeout) {
    session_timeout_ = timeout;
}

size_t UDPTunnelServer::get_active_clients_count() const {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    return active_clients_.size();
}

std::vector<ClientSession> UDPTunnelServer::get_active_sessions() const {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    std::vector<ClientSession> sessions;
    sessions.reserve(active_clients_.size());
    
    for (const auto& [client_id, client] : active_clients_) {
        sessions.push_back(client);
    }
    
    return sessions;
}

void UDPTunnelServer::server_loop() {
    uint8_t buffer[4096];
    sockaddr_in6 client_addr{};
    socklen_t addr_len = sizeof(client_addr);
    
    while (running_.load()) {
        ssize_t bytes_received = recvfrom(udp_socket_, buffer, sizeof(buffer), 0,
                                         reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        
        if (bytes_received < 0) {
            if (running_.load()) {
                logger_("error receiving udp data");
            }
            continue;
        }
        
        if (bytes_received == 0) {
            continue;
        }
        
        std::vector<uint8_t> packet_data(buffer, buffer + bytes_received);
        handle_udp_packet(packet_data, client_addr);
    }
}

void UDPTunnelServer::tun_packet_loop() {
    uint8_t buffer[4096];
    
    while (running_.load()) {
        std::vector<uint8_t> ip_packet;
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void UDPTunnelServer::handle_udp_packet(const std::vector<uint8_t>& packet, const sockaddr_in6& client_addr) {
    if (packet.size() < 8) {
        logger_("received invalid packet from client");
        return;
    }
    
    uint16_t packet_type = *reinterpret_cast<const uint16_t*>(packet.data());
    protocol::PacketType type = static_cast<protocol::PacketType>(packet_type);
    
    switch (type) {
        case protocol::PacketType::AUTH_REQUEST:
            handle_auth_packet_simple(packet, client_addr);
            break;
        case protocol::PacketType::DATA:
            handle_data_packet_simple(packet, client_addr);
            break;
        case protocol::PacketType::KEEPALIVE:
            handle_keepalive_packet_simple(packet, client_addr);
            break;
        case protocol::PacketType::DISCONNECT:
            handle_disconnect_packet_simple(packet, client_addr);
            break;
        default:
            logger_("received unknown packet type from client");
            break;
    }
}

void UDPTunnelServer::handle_auth_packet_simple(const std::vector<uint8_t>& packet, const sockaddr_in6& client_addr) {
    logger_("authentication request from client");
    
    std::string client_id = "client_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    std::string allocated_ip;
    
    if (!allocate_client_ip(client_id, allocated_ip)) {
        send_auth_response(client_addr, false, "");
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        
        if (active_clients_.size() >= max_clients_) {
            deallocate_client_ip(client_id);
            send_auth_response(client_addr, false, "");
            return;
        }
        
        ClientSession session;
        session.client_id = client_id;
        session.client_address = client_addr;
        session.allocated_ip = allocated_ip;
        session.state = protocol::SessionState::CONNECTED;
        session.last_activity = std::chrono::steady_clock::now();
        session.session_id = std::stoul(generate_session_id());
        
        active_clients_[client_id] = session;
        ip_to_client_map_[allocated_ip] = client_id;
    }
    
    send_auth_response(client_addr, true, allocated_ip);
    logger_("client authenticated - id: " + client_id + ", ip: " + allocated_ip);
}

void UDPTunnelServer::handle_data_packet_simple(const std::vector<uint8_t>& packet, const sockaddr_in6& client_addr) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    for (auto& [id, client] : active_clients_) {
        if (memcmp(&client.client_address, &client_addr, sizeof(sockaddr_in6)) == 0) {
            client.update_activity();
            logger_("data packet received from client: " + id);
            return;
        }
    }
    
    logger_("received data from unknown client");
}

void UDPTunnelServer::handle_keepalive_packet_simple(const std::vector<uint8_t>& packet, const sockaddr_in6& client_addr) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    for (auto& [id, client] : active_clients_) {
        if (memcmp(&client.client_address, &client_addr, sizeof(sockaddr_in6)) == 0) {
            client.update_activity();
            std::vector<uint8_t> keepalive_response = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            send_udp_packet(client_addr, keepalive_response);
            break;
        }
    }
}

void UDPTunnelServer::handle_disconnect_packet_simple(const std::vector<uint8_t>& packet, const sockaddr_in6& client_addr) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    for (auto it = active_clients_.begin(); it != active_clients_.end(); ++it) {
        if (memcmp(&it->second.client_address, &client_addr, sizeof(sockaddr_in6)) == 0) {
            deallocate_client_ip(it->first);
            ip_to_client_map_.erase(it->second.allocated_ip);
            logger_("client disconnected: " + it->first);
            active_clients_.erase(it);
            break;
        }
    }
}

void UDPTunnelServer::relay_tun_to_clients(const std::vector<uint8_t>& ip_packet) {
    std::string destination_ip = extract_destination_ip(ip_packet);
    if (destination_ip.empty()) {
        return;
    }
    
    std::string client_id = find_client_by_ip(destination_ip);
    if (!client_id.empty()) {
        relay_to_client(client_id, ip_packet);
    }
}

void UDPTunnelServer::relay_to_client(const std::string& client_id, const std::vector<uint8_t>& ip_packet) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    auto it = active_clients_.find(client_id);
    
    if (it != active_clients_.end()) {
        std::vector<uint8_t> data_packet = {0x03, 0x00};
        data_packet.insert(data_packet.end(), ip_packet.begin(), ip_packet.end());
        send_udp_packet(it->second.client_address, data_packet);
        it->second.update_activity();
    }
}

void UDPTunnelServer::broadcast_to_all_clients(const std::vector<uint8_t>& ip_packet) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    for (auto& [client_id, client] : active_clients_) {
        std::vector<uint8_t> data_packet = {0x03, 0x00};
        data_packet.insert(data_packet.end(), ip_packet.begin(), ip_packet.end());
        send_udp_packet(client.client_address, data_packet);
        client.update_activity();
    }
}

bool UDPTunnelServer::authenticate_client(const std::string& client_id, const std::string& auth_data) {
    return !client_id.empty() && !auth_data.empty();
}

bool UDPTunnelServer::allocate_client_ip(const std::string& client_id, std::string& allocated_ip) {
    auto ip_opt = ip_pool_->allocate_ip(client_id);
    if (ip_opt.has_value()) {
        allocated_ip = ip_opt.value();
        return true;
    }
    return false;
}

void UDPTunnelServer::deallocate_client_ip(const std::string& client_id) {
    ip_pool_->release_ip(client_id);
}

std::string UDPTunnelServer::generate_session_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(1, 0xFFFFFFFF);
    
    return std::to_string(dis(gen));
}

std::string UDPTunnelServer::extract_destination_ip(const std::vector<uint8_t>& ip_packet) {
    if (ip_packet.size() < 20) {
        return "";
    }
    
    uint32_t dest_ip = *reinterpret_cast<const uint32_t*>(ip_packet.data() + 16);
    return inet_ntoa(in_addr{dest_ip});
}

std::string UDPTunnelServer::find_client_by_ip(const std::string& destination_ip) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    auto it = ip_to_client_map_.find(destination_ip);
    return (it != ip_to_client_map_.end()) ? it->second : "";
}

void UDPTunnelServer::send_auth_response(const sockaddr_in6& client_addr, bool success, const std::string& allocated_ip) {
    std::vector<uint8_t> response_packet;
    response_packet.resize(64);
    
    uint16_t packet_type = static_cast<uint16_t>(protocol::PacketType::AUTH_RESPONSE);
    memcpy(response_packet.data(), &packet_type, 2);
    
    uint8_t result = success ? static_cast<uint8_t>(protocol::AuthResult::SUCCESS) : 
                               static_cast<uint8_t>(protocol::AuthResult::INVALID_CREDENTIALS);
    response_packet[8] = result;
    
    if (success && !allocated_ip.empty()) {
        strncpy(reinterpret_cast<char*>(response_packet.data() + 16), allocated_ip.c_str(), 
                std::min(allocated_ip.size(), size_t(32)));
    }
    
    send_udp_packet(client_addr, response_packet);
}

void UDPTunnelServer::send_udp_packet(const sockaddr_in6& client_addr, const std::vector<uint8_t>& packet) {
    ssize_t bytes_sent = sendto(udp_socket_, packet.data(), packet.size(), 0,
                               reinterpret_cast<const sockaddr*>(&client_addr), sizeof(client_addr));
    
    if (bytes_sent < 0) {
        logger_("failed to send packet to client");
    }
}

void UDPTunnelServer::setup_server_tun() {
    infrastructure::TunConfig config;
    config.device_name = "cspvpn0";
    config.local_ip = "10.8.0.1";
    config.remote_ip = "10.8.0.2";
    config.netmask = "255.255.255.0";
    config.mtu = 1500;
    config.persistent = false;
    
    if (!server_tun_->create_tun(config)) {
        logger_("failed to create tun interface");
        return;
    }
    
    configure_server_routing();
    enable_ip_forwarding();
}

void UDPTunnelServer::configure_server_routing() {
    logger_("configuring server routing");
}

void UDPTunnelServer::enable_ip_forwarding() {
    logger_("enabling ip forwarding");
}

void UDPTunnelServer::cleanup_expired_sessions() {
    while (running_.load()) {
        auto now = std::chrono::steady_clock::now();
        
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            
            for (auto it = active_clients_.begin(); it != active_clients_.end();) {
                if (it->second.is_expired(session_timeout_)) {
                    deallocate_client_ip(it->first);
                    ip_to_client_map_.erase(it->second.allocated_ip);
                    logger_("session expired: " + it->first);
                    it = active_clients_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

}
