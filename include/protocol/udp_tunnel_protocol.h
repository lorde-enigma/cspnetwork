#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <chrono>

namespace seeded_vpn::protocol {

enum class PacketType : uint16_t {
    AUTH_REQUEST = 0x0001,
    AUTH_RESPONSE = 0x0002,
    DATA = 0x0003,
    KEEPALIVE = 0x0004,
    DISCONNECT = 0x0005,
    ERROR_RESPONSE = 0x0006
};

enum class SessionState : uint8_t {
    HANDSHAKE = 0x01,
    CONNECTED = 0x02,
    DISCONNECTED = 0x03
};

enum class AuthResult : uint8_t {
    SUCCESS = 0x00,
    INVALID_CREDENTIALS = 0x01,
    SERVER_FULL = 0x02,
    IP_ALLOCATION_FAILED = 0x03,
    UNKNOWN_ERROR = 0x04
};

#pragma pack(push, 1)
struct TunnelPacketHeader {
    static constexpr uint32_t MAGIC = 0x43535056; // "CSPV"
    static constexpr uint16_t VERSION = 0x0001;
    
    uint32_t magic;
    uint16_t version;
    uint32_t session_id;
    PacketType packet_type;
    uint16_t payload_size;
    uint32_t sequence_number;
    uint64_t timestamp;
    uint32_t checksum;
};
#pragma pack(pop)

constexpr size_t TUNNEL_PACKET_HEADER_SIZE = sizeof(TunnelPacketHeader);

class TunnelPacket {
public:
    TunnelPacket();
    TunnelPacket(PacketType type, uint32_t session_id = 0);
    TunnelPacket(PacketType type, uint32_t session_id, const std::vector<uint8_t>& payload);
    
    static std::unique_ptr<TunnelPacket> deserialize(const std::vector<uint8_t>& data);
    std::vector<uint8_t> serialize() const;
    
    bool is_valid() const;
    void update_checksum();
    bool verify_checksum() const;
    
    // Getters
    PacketType get_type() const { return header_.packet_type; }
    uint32_t get_session_id() const { return header_.session_id; }
    uint32_t get_sequence_number() const { return header_.sequence_number; }
    uint64_t get_timestamp() const { return header_.timestamp; }
    const std::vector<uint8_t>& get_payload() const { return payload_; }
    size_t get_total_size() const { return TUNNEL_PACKET_HEADER_SIZE + payload_.size(); }
    
    // Setters
    void set_session_id(uint32_t session_id) { header_.session_id = session_id; }
    void set_sequence_number(uint32_t seq) { header_.sequence_number = seq; }
    void set_payload(const std::vector<uint8_t>& payload);
    
    // Factory methods for specific packet types
    static std::unique_ptr<TunnelPacket> create_auth_request(const std::string& client_id, const std::string& auth_token);
    static std::unique_ptr<TunnelPacket> create_auth_response(uint32_t session_id, AuthResult result, const std::string& allocated_ip = "");
    static std::unique_ptr<TunnelPacket> create_data_packet(uint32_t session_id, const std::vector<uint8_t>& ip_packet);
    static std::unique_ptr<TunnelPacket> create_keepalive(uint32_t session_id);
    static std::unique_ptr<TunnelPacket> create_disconnect(uint32_t session_id, const std::string& reason = "");
    static std::unique_ptr<TunnelPacket> create_error_response(const std::string& error_message);

private:
    TunnelPacketHeader header_;
    std::vector<uint8_t> payload_;
    
    uint32_t calculate_checksum() const;
    void initialize_header(PacketType type, uint32_t session_id);
};

// Utility functions for auth packets
struct AuthRequest {
    std::string client_id;
    std::string auth_token;
    uint64_t timestamp;
    
    static AuthRequest parse(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> serialize() const;
};

struct AuthResponse {
    AuthResult result;
    std::string allocated_ip;
    std::string server_config;
    
    static AuthResponse parse(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> serialize() const;
};

// Protocol constants
namespace constants {
    constexpr size_t MAX_PACKET_SIZE = 4096;
    constexpr size_t MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - TUNNEL_PACKET_HEADER_SIZE;
    constexpr std::chrono::seconds DEFAULT_KEEPALIVE_INTERVAL{30};
    constexpr std::chrono::seconds DEFAULT_SESSION_TIMEOUT{300};
    constexpr uint32_t MAX_SEQUENCE_NUMBER = 0xFFFFFFFF;
}

}
