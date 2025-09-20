#include "infrastructure/vpn_protocol.h"
#include <algorithm>
#include <chrono>
#include <openssl/sha.h>
#include <cstring>

namespace seeded_vpn::infrastructure {

std::vector<uint8_t> VPNPacketHeader::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(HEADER_SIZE);
    
    data.push_back(version);
    data.push_back(static_cast<uint8_t>(type));
    data.push_back(static_cast<uint8_t>(compression));
    data.push_back(flags);
    
    auto seq_bytes = reinterpret_cast<const uint8_t*>(&sequence_number);
    data.insert(data.end(), seq_bytes, seq_bytes + 4);
    
    auto len_bytes = reinterpret_cast<const uint8_t*>(&payload_length);
    data.insert(data.end(), len_bytes, len_bytes + 4);
    
    auto time_bytes = reinterpret_cast<const uint8_t*>(&timestamp);
    data.insert(data.end(), time_bytes, time_bytes + 8);
    
    data.insert(data.end(), checksum.begin(), checksum.end());
    
    return data;
}

VPNPacketHeader VPNPacketHeader::deserialize(const std::vector<uint8_t>& data) {
    VPNPacketHeader header;
    
    if (data.size() < HEADER_SIZE) {
        throw std::runtime_error("insufficient data for vpn header");
    }
    
    size_t offset = 0;
    header.version = data[offset++];
    header.type = static_cast<VPNPacketType>(data[offset++]);
    header.compression = static_cast<CompressionType>(data[offset++]);
    header.flags = data[offset++];
    
    memcpy(&header.sequence_number, &data[offset], 4);
    offset += 4;
    
    memcpy(&header.payload_length, &data[offset], 4);
    offset += 4;
    
    memcpy(&header.timestamp, &data[offset], 8);
    offset += 8;
    
    std::copy(data.begin() + offset, data.begin() + offset + 16, header.checksum.begin());
    
    return header;
}

bool VPNPacketHeader::is_valid() const {
    return version == 1 && 
           payload_length <= 65535 &&
           timestamp > 0;
}

VPNPacket::VPNPacket(VPNPacketType type, std::vector<uint8_t> payload) 
    : payload_(std::move(payload)) {
    header_.version = 1;
    header_.type = type;
    header_.compression = CompressionType::NONE;
    header_.flags = 0;
    header_.sequence_number = 0;
    header_.payload_length = static_cast<uint32_t>(payload_.size());
    header_.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    header_.checksum.fill(0);
    
    update_checksum();
}

void VPNPacket::set_sequence_number(uint32_t seq) {
    header_.sequence_number = seq;
    update_checksum();
}

void VPNPacket::set_compression(CompressionType compression) {
    header_.compression = compression;
    update_checksum();
}

void VPNPacket::set_flags(uint8_t flags) {
    header_.flags = flags;
    update_checksum();
}

void VPNPacket::set_payload(std::vector<uint8_t> payload) {
    payload_ = std::move(payload);
    header_.payload_length = static_cast<uint32_t>(payload_.size());
    update_checksum();
}

VPNPacketType VPNPacket::get_type() const {
    return header_.type;
}

uint32_t VPNPacket::get_sequence_number() const {
    return header_.sequence_number;
}

const std::vector<uint8_t>& VPNPacket::get_payload() const {
    return payload_;
}

size_t VPNPacket::get_total_size() const {
    return VPNPacketHeader::HEADER_SIZE + payload_.size();
}

std::vector<uint8_t> VPNPacket::serialize() const {
    auto header_data = header_.serialize();
    header_data.insert(header_data.end(), payload_.begin(), payload_.end());
    return header_data;
}

VPNPacket VPNPacket::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < VPNPacketHeader::HEADER_SIZE) {
        throw std::runtime_error("insufficient data for vpn packet");
    }
    
    auto header = VPNPacketHeader::deserialize(data);
    
    if (data.size() < VPNPacketHeader::HEADER_SIZE + header.payload_length) {
        throw std::runtime_error("insufficient payload data");
    }
    
    std::vector<uint8_t> payload(
        data.begin() + VPNPacketHeader::HEADER_SIZE,
        data.begin() + VPNPacketHeader::HEADER_SIZE + header.payload_length
    );
    
    VPNPacket packet(header.type, std::move(payload));
    packet.header_ = header;
    
    return packet;
}

bool VPNPacket::verify_checksum() const {
    auto calculated = calculate_checksum();
    return std::equal(calculated.begin(), calculated.end(), header_.checksum.begin());
}

void VPNPacket::update_checksum() {
    header_.checksum = calculate_checksum();
}

std::array<uint8_t, 16> VPNPacket::calculate_checksum() const {
    std::vector<uint8_t> data_for_hash;
    data_for_hash.push_back(header_.version);
    data_for_hash.push_back(static_cast<uint8_t>(header_.type));
    data_for_hash.push_back(static_cast<uint8_t>(header_.compression));
    data_for_hash.push_back(header_.flags);
    
    auto seq_bytes = reinterpret_cast<const uint8_t*>(&header_.sequence_number);
    data_for_hash.insert(data_for_hash.end(), seq_bytes, seq_bytes + 4);
    
    auto len_bytes = reinterpret_cast<const uint8_t*>(&header_.payload_length);
    data_for_hash.insert(data_for_hash.end(), len_bytes, len_bytes + 4);
    
    auto time_bytes = reinterpret_cast<const uint8_t*>(&header_.timestamp);
    data_for_hash.insert(data_for_hash.end(), time_bytes, time_bytes + 8);
    
    data_for_hash.insert(data_for_hash.end(), payload_.begin(), payload_.end());
    
    std::array<uint8_t, 16> hash;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data_for_hash.data(), data_for_hash.size());
    SHA256_Final(hash.data(), &sha256);
    
    return hash;
}

VPNStateMachine::VPNStateMachine() 
    : current_state_(VPNConnectionState::DISCONNECTED)
    , handshake_timeout_ms_(30000)
    , keepalive_interval_ms_(60000) {
    update_activity();
}

void VPNStateMachine::process_packet(const VPNPacket& packet) {
    update_activity();
    
    switch (packet.get_type()) {
        case VPNPacketType::HANDSHAKE_INIT:
            handle_handshake_init(packet);
            break;
        case VPNPacketType::HANDSHAKE_RESPONSE:
            handle_handshake_response(packet);
            break;
        case VPNPacketType::HANDSHAKE_COMPLETE:
            handle_handshake_complete(packet);
            break;
        case VPNPacketType::DATA_PACKET:
            handle_data_packet(packet);
            break;
        case VPNPacketType::KEEPALIVE:
            handle_keepalive(packet);
            break;
        case VPNPacketType::DISCONNECT:
            handle_disconnect(packet);
            break;
        case VPNPacketType::ERROR_RESPONSE:
            handle_error_response(packet);
            break;
    }
}

void VPNStateMachine::initiate_handshake() {
    if (current_state_ == VPNConnectionState::DISCONNECTED) {
        transition_to(VPNConnectionState::CONNECTING);
    }
}

void VPNStateMachine::handle_timeout() {
    if (is_timeout_expired()) {
        switch (current_state_) {
            case VPNConnectionState::CONNECTING:
            case VPNConnectionState::AUTHENTICATING:
                transition_to(VPNConnectionState::ERROR_STATE);
                break;
            case VPNConnectionState::CONNECTED:
                transition_to(VPNConnectionState::DISCONNECTED);
                break;
            default:
                break;
        }
    }
}

void VPNStateMachine::disconnect() {
    transition_to(VPNConnectionState::DISCONNECTING);
    transition_to(VPNConnectionState::DISCONNECTED);
}

VPNConnectionState VPNStateMachine::get_state() const {
    return current_state_;
}

bool VPNStateMachine::is_connected() const {
    return current_state_ == VPNConnectionState::CONNECTED;
}

bool VPNStateMachine::can_send_data() const {
    return current_state_ == VPNConnectionState::CONNECTED;
}

void VPNStateMachine::set_state_change_callback(std::function<void(VPNConnectionState, VPNConnectionState)> callback) {
    state_change_callback_ = std::move(callback);
}

void VPNStateMachine::transition_to(VPNConnectionState new_state) {
    auto old_state = current_state_;
    current_state_ = new_state;
    
    if (state_change_callback_) {
        state_change_callback_(old_state, new_state);
    }
    
    update_activity();
}

void VPNStateMachine::handle_handshake_init(const VPNPacket& packet) {
    if (current_state_ == VPNConnectionState::DISCONNECTED) {
        transition_to(VPNConnectionState::AUTHENTICATING);
    }
}

void VPNStateMachine::handle_handshake_response(const VPNPacket& packet) {
    if (current_state_ == VPNConnectionState::CONNECTING) {
        transition_to(VPNConnectionState::AUTHENTICATING);
    }
}

void VPNStateMachine::handle_handshake_complete(const VPNPacket& packet) {
    if (current_state_ == VPNConnectionState::AUTHENTICATING) {
        transition_to(VPNConnectionState::CONNECTED);
    }
}

void VPNStateMachine::handle_data_packet(const VPNPacket& packet) {
    if (current_state_ != VPNConnectionState::CONNECTED) {
        transition_to(VPNConnectionState::ERROR_STATE);
    }
}

void VPNStateMachine::handle_keepalive(const VPNPacket& packet) {
    if (current_state_ == VPNConnectionState::CONNECTED) {
        update_activity();
    }
}

void VPNStateMachine::handle_disconnect(const VPNPacket& packet) {
    transition_to(VPNConnectionState::DISCONNECTED);
}

void VPNStateMachine::handle_error_response(const VPNPacket& packet) {
    transition_to(VPNConnectionState::ERROR_STATE);
}

bool VPNStateMachine::is_timeout_expired() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_activity_);
    
    switch (current_state_) {
        case VPNConnectionState::CONNECTING:
        case VPNConnectionState::AUTHENTICATING:
            return elapsed.count() > handshake_timeout_ms_;
        case VPNConnectionState::CONNECTED:
            return elapsed.count() > keepalive_interval_ms_ * 2;
        default:
            return false;
    }
}

void VPNStateMachine::update_activity() {
    last_activity_ = std::chrono::steady_clock::now();
}

VPNProtocolHandler::VPNProtocolHandler() 
    : next_sequence_number_(1) {
}

void VPNProtocolHandler::initialize(const domain::ConnectionParameters& params) {
    state_machine_.set_state_change_callback([this](VPNConnectionState old_state, VPNConnectionState new_state) {
        if (new_state == VPNConnectionState::ERROR_STATE && error_handler_) {
            error_handler_("state machine error transition");
        }
    });
}

std::vector<uint8_t> VPNProtocolHandler::encapsulate_ipv6_packet(const std::vector<uint8_t>& ipv6_packet) {
    auto vpn_packet = create_data_packet(ipv6_packet);
    return vpn_packet.serialize();
}

std::vector<uint8_t> VPNProtocolHandler::decapsulate_vpn_packet(const std::vector<uint8_t>& vpn_packet) {
    try {
        auto packet = VPNPacket::deserialize(vpn_packet);
        
        if (!packet.verify_checksum()) {
            if (error_handler_) {
                error_handler_("checksum verification failed");
            }
            return {};
        }
        
        state_machine_.process_packet(packet);
        
        if (packet.get_type() == VPNPacketType::DATA_PACKET) {
            return packet.get_payload();
        }
        
        return {};
    } catch (const std::exception& e) {
        if (error_handler_) {
            error_handler_(std::string("decapsulation error: ") + e.what());
        }
        return {};
    }
}

VPNPacket VPNProtocolHandler::create_handshake_init(const std::string& client_id) {
    std::vector<uint8_t> payload(client_id.begin(), client_id.end());
    VPNPacket packet(VPNPacketType::HANDSHAKE_INIT, payload);
    packet.set_sequence_number(get_next_sequence_number());
    return packet;
}

VPNPacket VPNProtocolHandler::create_handshake_response(uint64_t challenge) {
    std::vector<uint8_t> payload(8);
    std::memcpy(payload.data(), &challenge, 8);
    VPNPacket packet(VPNPacketType::HANDSHAKE_RESPONSE, payload);
    packet.set_sequence_number(get_next_sequence_number());
    return packet;
}

VPNPacket VPNProtocolHandler::create_handshake_complete() {
    VPNPacket packet(VPNPacketType::HANDSHAKE_COMPLETE);
    packet.set_sequence_number(get_next_sequence_number());
    return packet;
}

VPNPacket VPNProtocolHandler::create_data_packet(const std::vector<uint8_t>& data) {
    VPNPacket packet(VPNPacketType::DATA_PACKET, data);
    packet.set_sequence_number(get_next_sequence_number());
    return packet;
}

VPNPacket VPNProtocolHandler::create_keepalive() {
    VPNPacket packet(VPNPacketType::KEEPALIVE);
    packet.set_sequence_number(get_next_sequence_number());
    return packet;
}

VPNPacket VPNProtocolHandler::create_disconnect(const std::string& reason) {
    std::vector<uint8_t> payload(reason.begin(), reason.end());
    VPNPacket packet(VPNPacketType::DISCONNECT, payload);
    packet.set_sequence_number(get_next_sequence_number());
    return packet;
}

VPNPacket VPNProtocolHandler::create_error_response(const std::string& error) {
    std::vector<uint8_t> payload(error.begin(), error.end());
    VPNPacket packet(VPNPacketType::ERROR_RESPONSE, payload);
    packet.set_sequence_number(get_next_sequence_number());
    return packet;
}

void VPNProtocolHandler::process_incoming_packet(const std::vector<uint8_t>& raw_data) {
    if (!validate_packet_structure(raw_data)) {
        if (error_handler_) {
            error_handler_("invalid packet structure");
        }
        return;
    }
    
    try {
        auto packet = VPNPacket::deserialize(raw_data);
        
        if (packet_handler_) {
            packet_handler_(packet);
        }
        
        state_machine_.process_packet(packet);
    } catch (const std::exception& e) {
        if (error_handler_) {
            error_handler_(std::string("packet processing error: ") + e.what());
        }
    }
}

std::vector<std::vector<uint8_t>> VPNProtocolHandler::get_outgoing_packets() {
    auto packets = std::move(outgoing_queue_);
    outgoing_queue_.clear();
    return packets;
}

void VPNProtocolHandler::set_packet_handler(std::function<void(const VPNPacket&)> handler) {
    packet_handler_ = std::move(handler);
}

void VPNProtocolHandler::set_error_handler(std::function<void(const std::string&)> handler) {
    error_handler_ = std::move(handler);
}

bool VPNProtocolHandler::validate_packet_structure(const std::vector<uint8_t>& data) {
    return data.size() >= VPNPacketHeader::HEADER_SIZE;
}

void VPNProtocolHandler::queue_outgoing_packet(const VPNPacket& packet) {
    outgoing_queue_.push_back(packet.serialize());
}

uint32_t VPNProtocolHandler::get_next_sequence_number() {
    return next_sequence_number_++;
}

VPNFragmentationHandler::VPNFragmentationHandler(size_t max_fragment_size) 
    : max_fragment_size_(max_fragment_size)
    , fragment_timeout_(std::chrono::seconds(30)) {
}

std::vector<VPNPacket> VPNFragmentationHandler::fragment_packet(const VPNPacket& packet) {
    std::vector<VPNPacket> fragments;
    
    if (packet.get_total_size() <= max_fragment_size_) {
        fragments.push_back(packet);
        return fragments;
    }
    
    auto payload = packet.get_payload();
    size_t total_fragments = (payload.size() + max_fragment_size_ - 1) / max_fragment_size_;
    uint32_t fragment_id = packet.get_sequence_number();
    
    for (size_t i = 0; i < total_fragments; ++i) {
        size_t start = i * max_fragment_size_;
        size_t end = std::min(start + max_fragment_size_, payload.size());
        
        std::vector<uint8_t> fragment_payload(payload.begin() + start, payload.begin() + end);
        
        VPNPacket fragment(packet.get_type(), fragment_payload);
        fragment.set_sequence_number(fragment_id);
        fragment.set_flags(static_cast<uint8_t>(i) | (i == total_fragments - 1 ? 0x80 : 0x00));
        
        fragments.push_back(fragment);
    }
    
    return fragments;
}

std::optional<VPNPacket> VPNFragmentationHandler::reassemble_fragments(const VPNPacket& fragment) {
    if (!is_fragmented_packet(fragment)) {
        return fragment;
    }
    
    uint32_t fragment_id = get_fragment_id(fragment);
    fragment_buffers_[fragment_id].push_back(fragment);
    fragment_timestamps_[fragment_id] = std::chrono::steady_clock::now();
    
    if (all_fragments_received(fragment_id)) {
        auto& fragments = fragment_buffers_[fragment_id];
        
        std::sort(fragments.begin(), fragments.end(), 
                  [](const VPNPacket& a, const VPNPacket& b) {
                      return (a.get_sequence_number() & 0xFF) < (b.get_sequence_number() & 0xFF);
                  });
        
        std::vector<uint8_t> reassembled_payload;
        for (const auto& frag : fragments) {
            const auto& frag_payload = frag.get_payload();
            reassembled_payload.insert(reassembled_payload.end(), 
                                       frag_payload.begin(), frag_payload.end());
        }
        
        VPNPacket reassembled(fragments[0].get_type(), reassembled_payload);
        reassembled.set_sequence_number(fragment_id);
        
        fragment_buffers_.erase(fragment_id);
        fragment_timestamps_.erase(fragment_id);
        
        return reassembled;
    }
    
    return std::nullopt;
}

void VPNFragmentationHandler::cleanup_expired_fragments() {
    auto now = std::chrono::steady_clock::now();
    
    auto it = fragment_timestamps_.begin();
    while (it != fragment_timestamps_.end()) {
        if (now - it->second > fragment_timeout_) {
            fragment_buffers_.erase(it->first);
            it = fragment_timestamps_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t VPNFragmentationHandler::get_pending_fragments_count() const {
    return fragment_buffers_.size();
}

bool VPNFragmentationHandler::is_fragmented_packet(const VPNPacket& packet) {
    return (packet.get_sequence_number() & 0x40000000) != 0;
}

uint32_t VPNFragmentationHandler::get_fragment_id(const VPNPacket& packet) {
    return packet.get_sequence_number() & 0x3FFFFFFF;
}

bool VPNFragmentationHandler::all_fragments_received(uint32_t fragment_id) const {
    auto it = fragment_buffers_.find(fragment_id);
    if (it == fragment_buffers_.end()) {
        return false;
    }
    
    const auto& fragments = it->second;
    if (fragments.empty()) {
        return false;
    }
    
    return std::any_of(fragments.begin(), fragments.end(), 
                       [](const VPNPacket& frag) {
                           return (frag.get_sequence_number() & 0x80) != 0;
                       });
}

}
