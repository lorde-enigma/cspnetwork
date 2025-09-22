#include "protocol/udp_tunnel_protocol.h"
#include "infrastructure/crc32.h"
#include <cstring>
#include <chrono>

namespace seeded_vpn::protocol {

TunnelPacket::TunnelPacket() {
    initialize_header(PacketType::DATA, 0);
}

TunnelPacket::TunnelPacket(PacketType type, uint32_t session_id) {
    initialize_header(type, session_id);
}

TunnelPacket::TunnelPacket(PacketType type, uint32_t session_id, const std::vector<uint8_t>& payload)
    : payload_(payload) {
    initialize_header(type, session_id);
    header_.payload_size = static_cast<uint16_t>(payload_.size());
    update_checksum();
}

void TunnelPacket::initialize_header(PacketType type, uint32_t session_id) {
    header_.magic = TunnelPacketHeader::MAGIC;
    header_.version = TunnelPacketHeader::VERSION;
    header_.packet_type = type;
    header_.session_id = session_id;
    header_.payload_size = 0;
    header_.sequence_number = 0;
    header_.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    header_.checksum = 0;
}

std::unique_ptr<TunnelPacket> TunnelPacket::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < TUNNEL_PACKET_HEADER_SIZE) {
        return nullptr;
    }
    
    TunnelPacketHeader header;
    std::memcpy(&header, data.data(), TUNNEL_PACKET_HEADER_SIZE);
    
    if (header.magic != TunnelPacketHeader::MAGIC || 
        header.version != TunnelPacketHeader::VERSION) {
        return nullptr;
    }
    
    if (data.size() < TUNNEL_PACKET_HEADER_SIZE + header.payload_size) {
        return nullptr;
    }
    
    std::vector<uint8_t> payload;
    if (header.payload_size > 0) {
        payload.assign(
            data.begin() + TUNNEL_PACKET_HEADER_SIZE,
            data.begin() + TUNNEL_PACKET_HEADER_SIZE + header.payload_size
        );
    }
    
    auto packet = std::make_unique<TunnelPacket>(header.packet_type, header.session_id, payload);
    packet->header_ = header;
    
    if (!packet->verify_checksum()) {
        return nullptr;
    }
    
    return packet;
}

std::vector<uint8_t> TunnelPacket::serialize() const {
    std::vector<uint8_t> data;
    data.resize(TUNNEL_PACKET_HEADER_SIZE + payload_.size());
    
    std::memcpy(data.data(), &header_, TUNNEL_PACKET_HEADER_SIZE);
    
    if (!payload_.empty()) {
        std::memcpy(data.data() + TUNNEL_PACKET_HEADER_SIZE, payload_.data(), payload_.size());
    }
    
    return data;
}

bool TunnelPacket::is_valid() const {
    return header_.magic == TunnelPacketHeader::MAGIC &&
           header_.version == TunnelPacketHeader::VERSION &&
           header_.payload_size == payload_.size() &&
           verify_checksum();
}

void TunnelPacket::update_checksum() {
    header_.checksum = 0;
    header_.checksum = calculate_checksum();
}

bool TunnelPacket::verify_checksum() const {
    uint32_t stored_checksum = header_.checksum;
    const_cast<TunnelPacket*>(this)->header_.checksum = 0;
    uint32_t calculated = calculate_checksum();
    const_cast<TunnelPacket*>(this)->header_.checksum = stored_checksum;
    return calculated == stored_checksum;
}

uint32_t TunnelPacket::calculate_checksum() const {
    std::vector<uint8_t> data_for_checksum;
    data_for_checksum.resize(TUNNEL_PACKET_HEADER_SIZE + payload_.size());
    
    std::memcpy(data_for_checksum.data(), &header_, TUNNEL_PACKET_HEADER_SIZE);
    
    if (!payload_.empty()) {
        std::memcpy(data_for_checksum.data() + TUNNEL_PACKET_HEADER_SIZE, payload_.data(), payload_.size());
    }
    
    return infrastructure::CRC32::calculate(data_for_checksum.data(), data_for_checksum.size());
}

void TunnelPacket::set_payload(const std::vector<uint8_t>& payload) {
    payload_ = payload;
    header_.payload_size = static_cast<uint16_t>(payload_.size());
    update_checksum();
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_auth_request(const std::string& client_id, const std::string& auth_token) {
    AuthRequest req;
    req.client_id = client_id;
    req.auth_token = auth_token;
    req.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    auto payload = req.serialize();
    return std::make_unique<TunnelPacket>(PacketType::AUTH_REQUEST, 0, payload);
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_auth_response(uint32_t session_id, AuthResult result, const std::string& allocated_ip) {
    AuthResponse resp;
    resp.result = result;
    resp.allocated_ip = allocated_ip;
    resp.server_config = "";
    
    auto payload = resp.serialize();
    return std::make_unique<TunnelPacket>(PacketType::AUTH_RESPONSE, session_id, payload);
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_data_packet(uint32_t session_id, const std::vector<uint8_t>& ip_packet) {
    return std::make_unique<TunnelPacket>(PacketType::DATA, session_id, ip_packet);
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_keepalive(uint32_t session_id) {
    return std::make_unique<TunnelPacket>(PacketType::KEEPALIVE, session_id);
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_disconnect(uint32_t session_id, const std::string& reason) {
    std::vector<uint8_t> payload(reason.begin(), reason.end());
    return std::make_unique<TunnelPacket>(PacketType::DISCONNECT, session_id, payload);
}

std::unique_ptr<TunnelPacket> TunnelPacket::create_error_response(const std::string& error_message) {
    std::vector<uint8_t> payload(error_message.begin(), error_message.end());
    return std::make_unique<TunnelPacket>(PacketType::ERROR_RESPONSE, 0, payload);
}

}
