#include "protocol/udp_tunnel_protocol.h"
#include "infrastructure/tun_interface.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <signal.h>
#include <cstdlib>

using namespace seeded_vpn::protocol;
using namespace seeded_vpn::infrastructure;

class VPNClient {
private:
    int udp_sock_;
    TunInterface tun_interface_;
    std::string server_host_;
    uint16_t server_port_;
    sockaddr_in6 server_addr_;
    uint32_t session_id_;
    std::string allocated_ip_;
    std::atomic<bool> running_;
    std::thread udp_thread_;
    std::thread tun_thread_;

public:
    VPNClient(const std::string& server_host, uint16_t server_port)
        : udp_sock_(-1), server_host_(server_host), server_port_(server_port), 
          session_id_(0), running_(false) {
    }

    ~VPNClient() {
        stop();
    }

    bool start() {
        if (!create_udp_socket()) {
            std::cerr << "failed to create udp socket" << std::endl;
            return false;
        }

        if (!create_tun_interface()) {
            std::cerr << "failed to create tun interface" << std::endl;
            return false;
        }

        if (!authenticate()) {
            std::cerr << "authentication failed" << std::endl;
            return false;
        }

        if (!setup_routing()) {
            std::cerr << "failed to setup routing" << std::endl;
            return false;
        }

        running_ = true;
        udp_thread_ = std::thread(&VPNClient::udp_loop, this);
        tun_thread_ = std::thread(&VPNClient::tun_loop, this);

        return true;
    }

    void stop() {
        running_ = false;
        
        if (udp_thread_.joinable()) {
            udp_thread_.join();
        }
        
        if (tun_thread_.joinable()) {
            tun_thread_.join();
        }

        cleanup_routing();
        tun_interface_.destroy_tun();
        
        if (udp_sock_ >= 0) {
            close(udp_sock_);
            udp_sock_ = -1;
        }
    }

    void send_keepalive() {
        auto keepalive_packet = TunnelPacket::create_keepalive(session_id_);
        std::vector<uint8_t> keepalive_data = keepalive_packet->serialize();
        
        sendto(udp_sock_, keepalive_data.data(), keepalive_data.size(), 0,
               (struct sockaddr*)&server_addr_, sizeof(server_addr_));
    }

private:
    bool create_udp_socket() {
        udp_sock_ = socket(AF_INET6, SOCK_DGRAM, 0);
        if (udp_sock_ < 0) {
            return false;
        }

        memset(&server_addr_, 0, sizeof(server_addr_));
        server_addr_.sin6_family = AF_INET6;
        server_addr_.sin6_port = htons(server_port_);
        
        if (inet_pton(AF_INET6, server_host_.c_str(), &server_addr_.sin6_addr) <= 0) {
            if (inet_pton(AF_INET, server_host_.c_str(), &server_addr_.sin6_addr.s6_addr32[3]) > 0) {
                server_addr_.sin6_addr.s6_addr32[0] = 0;
                server_addr_.sin6_addr.s6_addr32[1] = 0;
                server_addr_.sin6_addr.s6_addr32[2] = htonl(0xFFFF);
            } else {
                return false;
            }
        }

        return true;
    }

    bool create_tun_interface() {
        TunConfig config;
        config.device_name = "vpn_client0";
        config.local_ip = "10.8.0.100";
        config.remote_ip = "10.8.0.1";
        config.netmask = "255.255.255.0";
        config.mtu = 1500;
        config.persistent = false;

        return tun_interface_.create_tun(config);
    }

    bool authenticate() {
        auto auth_packet = TunnelPacket::create_auth_request("vpn_client", "token123");
        std::vector<uint8_t> auth_data = auth_packet->serialize();

        if (sendto(udp_sock_, auth_data.data(), auth_data.size(), 0,
                   (struct sockaddr*)&server_addr_, sizeof(server_addr_)) < 0) {
            return false;
        }

        std::vector<uint8_t> response_data(1024);
        socklen_t addr_len = sizeof(server_addr_);
        ssize_t received = recvfrom(udp_sock_, response_data.data(), response_data.size(), 0,
                                    (struct sockaddr*)&server_addr_, &addr_len);

        if (received <= 0) {
            return false;
        }

        response_data.resize(received);
        auto response_packet = TunnelPacket::deserialize(response_data);
        
        if (!response_packet || response_packet->get_type() != PacketType::AUTH_RESPONSE) {
            return false;
        }

        const auto& payload = response_packet->get_payload();
        
        if (payload.empty() || payload[0] != static_cast<uint8_t>(AuthResult::SUCCESS)) {
            return false;
        }

        session_id_ = response_packet->get_session_id();
        
        if (payload.size() > 1) {
            allocated_ip_ = std::string(payload.begin() + 1, payload.end());
            std::cout << "allocated ip: " << allocated_ip_ << std::endl;
        }

        return true;
    }

    bool setup_routing() {
        std::string device = tun_interface_.get_device_name();
        
        std::string cmd1 = "ip route add default dev " + device + " metric 1";
        if (system(cmd1.c_str()) != 0) {
            std::cerr << "failed to add default route" << std::endl;
            return false;
        }

        std::string cmd2 = "ip -6 route add " + server_host_ + "/128 via $(ip -6 route | grep default | head -1 | awk '{print $3}')";
        if (system(cmd2.c_str()) != 0) {
            std::cerr << "failed to add server route" << std::endl;
        }

        return true;
    }

    void cleanup_routing() {
        std::string device = tun_interface_.get_device_name();
        
        std::string cmd1 = "ip route del default dev " + device + " metric 1";
        system(cmd1.c_str());
        
        std::string cmd2 = "ip -6 route del " + server_host_ + "/128";
        system(cmd2.c_str());
    }

    void udp_loop() {
        std::vector<uint8_t> buffer(4096);
        
        while (running_) {
            socklen_t addr_len = sizeof(server_addr_);
            ssize_t received = recvfrom(udp_sock_, buffer.data(), buffer.size(), 0,
                                        (struct sockaddr*)&server_addr_, &addr_len);

            if (received <= 0) {
                if (running_) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                continue;
            }

            buffer.resize(received);
            auto packet = TunnelPacket::deserialize(buffer);
            
            if (packet && packet->get_type() == PacketType::DATA) {
                const auto& payload = packet->get_payload();
                tun_interface_.send_packet(payload);
            }
        }
    }

    void tun_loop() {
        tun_interface_.set_packet_callback([this](const std::vector<uint8_t>& packet) {
            auto data_packet = TunnelPacket::create_data_packet(session_id_, packet);
            std::vector<uint8_t> serialized = data_packet->serialize();
            
            sendto(udp_sock_, serialized.data(), serialized.size(), 0,
                   (struct sockaddr*)&server_addr_, sizeof(server_addr_));
        });

        tun_interface_.start_packet_loop();
    }
};

std::unique_ptr<VPNClient> vpn_client;

void signal_handler(int signal) {
    std::cout << "received signal " << signal << ", shutting down..." << std::endl;
    if (vpn_client) {
        vpn_client->stop();
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <server_host> <server_port>" << std::endl;
        return 1;
    }

    if (getuid() != 0) {
        std::cerr << "this program must be run as root" << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::string server_host = argv[1];
    uint16_t server_port = static_cast<uint16_t>(std::stoul(argv[2]));

    vpn_client = std::make_unique<VPNClient>(server_host, server_port);

    if (!vpn_client->start()) {
        std::cerr << "failed to start vpn client" << std::endl;
        return 1;
    }

    std::cout << "vpn client started, press ctrl+c to stop" << std::endl;

    std::thread keepalive_thread([&]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            if (vpn_client) {
                vpn_client->send_keepalive();
            }
        }
    });

    keepalive_thread.detach();
    
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
