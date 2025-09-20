#pragma once

#include "domain/types.h"
#include <array>
#include <vector>
#include <memory>
#include <chrono>

namespace seeded_vpn::infrastructure {

class ChaCha20Poly1305 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    
    ChaCha20Poly1305(const std::array<uint8_t, KEY_SIZE>& key);
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, 
                                const std::array<uint8_t, NONCE_SIZE>& nonce,
                                const std::vector<uint8_t>& additional_data = {});
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                const std::array<uint8_t, NONCE_SIZE>& nonce,
                                const std::vector<uint8_t>& additional_data = {});
    
    void set_key(const std::array<uint8_t, KEY_SIZE>& key);
    std::array<uint8_t, NONCE_SIZE> generate_nonce();

private:
    std::array<uint8_t, KEY_SIZE> key_;
    uint64_t nonce_counter_;
};

struct HandshakeKeys {
    std::array<uint8_t, 32> client_to_server_key;
    std::array<uint8_t, 32> server_to_client_key;
    std::array<uint8_t, 32> handshake_key;
};

class KeyDerivation {
public:
    static std::array<uint8_t, 32> hkdf(const std::vector<uint8_t>& input_key,
                                       const std::vector<uint8_t>& salt,
                                       const std::vector<uint8_t>& info,
                                       size_t output_length = 32);
    
    static HandshakeKeys derive_session_keys(const std::vector<uint8_t>& shared_secret,
                                           const std::string& client_id,
                                           const std::string& server_id);
    
    static std::array<uint8_t, 32> derive_data_key(const std::array<uint8_t, 32>& session_key,
                                                   uint64_t packet_sequence);
    
    static std::vector<uint8_t> generate_random_bytes(size_t length);
};

enum class HandshakeState {
    INITIAL = 0,
    CLIENT_HELLO_SENT = 1,
    SERVER_HELLO_RECEIVED = 2,
    CLIENT_KEY_EXCHANGE_SENT = 3,
    SERVER_FINISHED_RECEIVED = 4,
    COMPLETED = 5,
    FAILED = 6
};

struct ClientHello {
    uint32_t protocol_version;
    std::array<uint8_t, 32> client_random;
    std::string client_id;
    std::vector<uint8_t> supported_ciphers;
    uint64_t timestamp;
};

struct ServerHello {
    uint32_t protocol_version;
    std::array<uint8_t, 32> server_random;
    std::string server_id;
    uint8_t selected_cipher;
    std::vector<uint8_t> server_certificate;
    uint64_t timestamp;
};

struct KeyExchange {
    std::vector<uint8_t> client_public_key;
    std::vector<uint8_t> client_certificate;
    std::vector<uint8_t> signature;
};

struct ServerFinished {
    std::vector<uint8_t> verify_data;
    std::vector<uint8_t> session_parameters;
};

class HandshakeProtocol {
public:
    HandshakeProtocol(bool is_server = true);
    
    void initialize_client(const std::string& client_id, const std::string& server_address);
    void initialize_server(const std::string& server_id, const std::vector<uint8_t>& server_certificate);
    
    std::vector<uint8_t> create_client_hello();
    std::vector<uint8_t> process_client_hello(const std::vector<uint8_t>& data);
    std::vector<uint8_t> process_server_hello(const std::vector<uint8_t>& data);
    std::vector<uint8_t> create_key_exchange();
    std::vector<uint8_t> process_key_exchange(const std::vector<uint8_t>& data);
    std::vector<uint8_t> create_server_finished();
    bool process_server_finished(const std::vector<uint8_t>& data);
    
    HandshakeState get_state() const;
    bool is_completed() const;
    HandshakeKeys get_session_keys() const;
    
    void set_timeout(std::chrono::milliseconds timeout);
    bool is_timeout_expired() const;

private:
    bool is_server_;
    HandshakeState state_;
    std::string client_id_;
    std::string server_id_;
    std::array<uint8_t, 32> client_random_;
    std::array<uint8_t, 32> server_random_;
    std::vector<uint8_t> client_private_key_;
    std::vector<uint8_t> client_public_key_;
    std::vector<uint8_t> server_public_key_;
    std::vector<uint8_t> shared_secret_;
    HandshakeKeys session_keys_;
    std::chrono::steady_clock::time_point handshake_start_;
    std::chrono::milliseconds timeout_;
    
    void generate_client_keypair();
    void calculate_shared_secret();
    std::vector<uint8_t> sign_data(const std::vector<uint8_t>& data);
    bool verify_signature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature);
    std::vector<uint8_t> serialize_client_hello(const ClientHello& hello);
    ClientHello deserialize_client_hello(const std::vector<uint8_t>& data);
    std::vector<uint8_t> serialize_server_hello(const ServerHello& hello);
    ServerHello deserialize_server_hello(const std::vector<uint8_t>& data);
    std::vector<uint8_t> serialize_key_exchange(const KeyExchange& exchange);
    KeyExchange deserialize_key_exchange(const std::vector<uint8_t>& data);
    std::vector<uint8_t> serialize_server_finished(const ServerFinished& finished);
    ServerFinished deserialize_server_finished(const std::vector<uint8_t>& data);
};

class CertificateValidator {
public:
    CertificateValidator();
    
    void add_trusted_ca(const std::vector<uint8_t>& ca_certificate);
    void set_certificate_store(const std::string& store_path);
    
    bool validate_certificate(const std::vector<uint8_t>& certificate,
                            const std::string& expected_identity = "");
    
    bool validate_certificate_chain(const std::vector<std::vector<uint8_t>>& certificate_chain);
    
    std::string extract_identity(const std::vector<uint8_t>& certificate);
    std::chrono::system_clock::time_point get_expiration_date(const std::vector<uint8_t>& certificate);
    
    bool is_certificate_revoked(const std::vector<uint8_t>& certificate);

private:
    std::vector<std::vector<uint8_t>> trusted_cas_;
    std::string certificate_store_path_;
    
    bool verify_signature_chain(const std::vector<std::vector<uint8_t>>& chain);
    bool check_validity_period(const std::vector<uint8_t>& certificate);
    bool check_key_usage(const std::vector<uint8_t>& certificate);
};

class AntiReplayProtection {
public:
    AntiReplayProtection(size_t window_size = 64);
    
    bool is_sequence_valid(uint64_t sequence_number);
    void mark_sequence_received(uint64_t sequence_number);
    void reset_window(uint64_t new_base_sequence);
    
    size_t get_window_size() const;
    uint64_t get_last_valid_sequence() const;

private:
    size_t window_size_;
    uint64_t highest_sequence_;
    std::vector<bool> received_bitmap_;
    
    bool is_in_window(uint64_t sequence_number) const;
    size_t get_bitmap_index(uint64_t sequence_number) const;
    void advance_window(uint64_t new_sequence);
};

class SecurityManager {
public:
    SecurityManager();
    
    void initialize(bool is_server, const std::string& identity);
    
    bool start_handshake(const std::string& peer_identity);
    std::vector<uint8_t> process_handshake_message(const std::vector<uint8_t>& message);
    bool is_handshake_complete() const;
    
    std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& plaintext, uint64_t sequence_number);
    std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& ciphertext, uint64_t sequence_number);
    
    bool validate_sequence_number(uint64_t sequence_number);
    void mark_sequence_processed(uint64_t sequence_number);
    
    void rotate_keys();
    bool is_key_rotation_needed() const;
    
    void set_certificate_validator(std::shared_ptr<CertificateValidator> validator);
    
    bool verify_packet_integrity(const std::vector<uint8_t>& packet_data, const std::string& client_id);
    bool encrypt_packet(const std::vector<uint8_t>& packet_data, const std::string& client_id, std::vector<uint8_t>& encrypted_data);

private:
    bool is_server_;
    std::string identity_;
    std::unique_ptr<HandshakeProtocol> handshake_;
    std::unique_ptr<ChaCha20Poly1305> data_cipher_;
    std::unique_ptr<AntiReplayProtection> replay_protection_;
    std::shared_ptr<CertificateValidator> cert_validator_;
    HandshakeKeys current_keys_;
    uint64_t packets_encrypted_;
    std::chrono::steady_clock::time_point last_key_rotation_;
    
    void derive_packet_keys(uint64_t sequence_number);
    bool should_rotate_keys() const;
};

}
