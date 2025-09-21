#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <optional>

namespace seeded_vpn::protocol {

enum class PacketType : uint8_t {
    AUTH_REQUEST = 0x01,
    AUTH_RESPONSE = 0x02,
    DATA = 0x03,
    KEEPALIVE = 0x04,
    DISCONNECT = 0x05,
    ERROR_RESPONSE = 0x06
};

enum class AuthResult : uint8_t {
    SUCCESS = 0x00,
    FAILED = 0x01,
    INVALID_CREDENTIALS = 0x02,
    SERVER_FULL = 0x03
};

enum class SessionState : uint8_t {
    DISCONNECTED = 0x00,
    AUTHENTICATING = 0x01,
    CONNECTED = 0x02,
    DISCONNECTING = 0x03,
    ERROR = 0x04
};

class TunnelPacket {
public:
    static std::unique_ptr<TunnelPacket> parse(const uint8_t* data, size_t size);
    static std::unique_ptr<TunnelPacket> create_auth_request(const std::string& credentials);
    static std::unique_ptr<TunnelPacket> create_auth_response(AuthResult result, const std::string& allocated_ip);
    static std::unique_ptr<TunnelPacket> create_data_packet(uint32_t session_id, const std::vector<uint8_t>& payload);
    static std::unique_ptr<TunnelPacket> create_keepalive(uint32_t session_id);
    static std::unique_ptr<TunnelPacket> create_disconnect(uint32_t session_id);
    static std::unique_ptr<TunnelPacket> create_error_response(const std::string& error_message);

    PacketType get_type() const { return type_; }
    uint32_t get_session_id() const { return session_id_; }
    size_t get_data_size() const { return payload_.size(); }
    void get_data_payload(uint8_t* buffer) const;
    
    std::vector<uint8_t> serialize() const;

private:
    TunnelPacket(PacketType type, uint32_t session_id, std::vector<uint8_t> payload);
    
    PacketType type_;
    uint32_t session_id_;
    std::vector<uint8_t> payload_;
    uint32_t crc32_;
    
    void calculate_crc();
    bool verify_crc(const uint8_t* data, size_t size) const;
};

}
