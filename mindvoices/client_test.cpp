#include "protocol/udp_tunnel_protocol.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <thread>
#include <chrono>

using namespace seeded_vpn::protocol;

class SimpleUDPClient {
private:
    int sock_;
    struct sockaddr_in6 server_addr_;
    std::string client_id_;
    
public:
    SimpleUDPClient(const std::string& server_ip, int port, const std::string& client_id) 
        : client_id_(client_id) {
        
        sock_ = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sock_ < 0) {
            throw std::runtime_error("failed to create socket");
        }
        
        memset(&server_addr_, 0, sizeof(server_addr_));
        server_addr_.sin6_family = AF_INET6;
        server_addr_.sin6_port = htons(port);
        
        if (server_ip == "localhost" || server_ip == "127.0.0.1") {
            inet_pton(AF_INET6, "::1", &server_addr_.sin6_addr);
        } else {
            inet_pton(AF_INET6, server_ip.c_str(), &server_addr_.sin6_addr);
        }
        
        std::cout << "[client] created socket, connecting to port " << port << std::endl;
    }
    
    ~SimpleUDPClient() {
        if (sock_ >= 0) {
            close(sock_);
        }
    }
    
    bool send_auth_request() {
        auto packet = TunnelPacket::create_auth_request(client_id_, "test_token");
        auto data = packet->serialize();
        
        ssize_t sent = sendto(sock_, data.data(), data.size(), 0, 
                            (struct sockaddr*)&server_addr_, sizeof(server_addr_));
        
        if (sent < 0) {
            std::cerr << "[client] failed to send auth request" << std::endl;
            return false;
        }
        
        std::cout << "[client] sent auth request (" << sent << " bytes)" << std::endl;
        return true;
    }
    
    bool receive_auth_response() {
        std::vector<uint8_t> buffer(4096);
        struct sockaddr_in6 from_addr;
        socklen_t from_len = sizeof(from_addr);
        
        std::cout << "[client] waiting for auth response..." << std::endl;
        
        ssize_t received = recvfrom(sock_, buffer.data(), buffer.size(), 0,
                                  (struct sockaddr*)&from_addr, &from_len);
        
        if (received < 0) {
            std::cerr << "[client] failed to receive auth response" << std::endl;
            return false;
        }
        
        std::cout << "[client] received " << received << " bytes" << std::endl;
        
        buffer.resize(received);
        auto packet = TunnelPacket::deserialize(buffer);
        
        if (!packet) {
            std::cerr << "[client] failed to parse response packet" << std::endl;
            return false;
        }
        
        if (packet->get_type() == PacketType::AUTH_RESPONSE) {
            auto payload = packet->get_payload();
            if (!payload.empty()) {
                AuthResponse response = AuthResponse::parse(payload);
                std::cout << "[client] auth result: " << static_cast<int>(response.result) << std::endl;
                if (response.result == AuthResult::SUCCESS) {
                    std::cout << "[client] allocated IP: " << response.allocated_ip << std::endl;
                    return true;
                }
            }
        } else if (packet->get_type() == PacketType::ERROR_RESPONSE) {
            auto payload = packet->get_payload();
            std::string error(payload.begin(), payload.end());
            std::cout << "[client] server error: " << error << std::endl;
        }
        
        return false;
    }
    
    void send_keepalive(uint32_t session_id) {
        auto packet = TunnelPacket::create_keepalive(session_id);
        auto data = packet->serialize();
        
        ssize_t sent = sendto(sock_, data.data(), data.size(), 0,
                            (struct sockaddr*)&server_addr_, sizeof(server_addr_));
        
        if (sent > 0) {
            std::cout << "[client] sent keepalive" << std::endl;
        }
    }
    
    void test_connection() {
        std::cout << "[client] testing connection to server..." << std::endl;
        
        if (!send_auth_request()) {
            return;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        if (receive_auth_response()) {
            std::cout << "[client] authentication successful!" << std::endl;
            
            for (int i = 0; i < 3; i++) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                send_keepalive(12345);
            }
        } else {
            std::cout << "[client] authentication failed" << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    std::string server_ip = "localhost";
    int port = 8080;
    std::string client_id = "test_client_001";
    
    if (argc > 1) {
        server_ip = argv[1];
    }
    if (argc > 2) {
        port = std::stoi(argv[2]);
    }
    if (argc > 3) {
        client_id = argv[3];
    }
    
    try {
        SimpleUDPClient client(server_ip, port, client_id);
        client.test_connection();
    } catch (const std::exception& e) {
        std::cerr << "[client] error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
