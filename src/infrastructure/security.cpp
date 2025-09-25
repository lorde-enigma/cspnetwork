#include "infrastructure/security.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <algorithm>
#include <stdexcept>
#include <cstring>

namespace seeded_vpn::infrastructure {

ChaCha20Poly1305::ChaCha20Poly1305(const std::array<uint8_t, KEY_SIZE>& key) 
    : key_(key), nonce_counter_(0) {
}

std::vector<uint8_t> ChaCha20Poly1305::encrypt(const std::vector<uint8_t>& plaintext,
                                              const std::array<uint8_t, NONCE_SIZE>& nonce,
                                              const std::vector<uint8_t>& additional_data) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("failed to create cipher context");
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to initialize encryption");
    }
    
    int len;
    if (!additional_data.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, additional_data.data(), additional_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("failed to process additional data");
        }
    }
    
    std::vector<uint8_t> ciphertext(plaintext.size() + TAG_SIZE);
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to encrypt data");
    }
    
    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to finalize encryption");
    }
    
    ciphertext_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, ciphertext.data() + ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to get authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len + TAG_SIZE);
    return ciphertext;
}

std::vector<uint8_t> ChaCha20Poly1305::decrypt(const std::vector<uint8_t>& ciphertext,
                                              const std::array<uint8_t, NONCE_SIZE>& nonce,
                                              const std::vector<uint8_t>& additional_data) {
    if (ciphertext.size() < TAG_SIZE) {
        throw std::runtime_error("ciphertext too short");
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("failed to create cipher context");
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to initialize decryption");
    }
    
    int len;
    if (!additional_data.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, additional_data.data(), additional_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("failed to process additional data");
        }
    }
    
    size_t plaintext_len = ciphertext.size() - TAG_SIZE;
    std::vector<uint8_t> plaintext(plaintext_len);
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to decrypt data");
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, 
                           const_cast<uint8_t*>(ciphertext.data() + plaintext_len)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to set authentication tag");
    }
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("decryption failed - authentication error");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

void ChaCha20Poly1305::set_key(const std::array<uint8_t, KEY_SIZE>& key) {
    key_ = key;
    nonce_counter_ = 0;
}

std::array<uint8_t, ChaCha20Poly1305::NONCE_SIZE> ChaCha20Poly1305::generate_nonce() {
    std::array<uint8_t, NONCE_SIZE> nonce;
    
    auto counter_bytes = reinterpret_cast<uint8_t*>(&nonce_counter_);
    std::copy(counter_bytes, counter_bytes + 8, nonce.begin());
    
    if (RAND_bytes(nonce.data() + 8, 4) != 1) {
        throw std::runtime_error("failed to generate random nonce suffix");
    }
    
    nonce_counter_++;
    return nonce;
}

std::array<uint8_t, 32> KeyDerivation::hkdf(const std::vector<uint8_t>& input_key,
                                           const std::vector<uint8_t>& salt,
                                           const std::vector<uint8_t>& info,
                                           size_t output_length) {
    std::array<uint8_t, 32> output;
    size_t output_len = output_length;
    
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        throw std::runtime_error("failed to create hkdf context");
    }
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("failed to initialize hkdf derivation");
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("failed to set hkdf hash function");
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, input_key.data(), input_key.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("failed to set hkdf key");
    }
    
    if (!salt.empty()) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("failed to set hkdf salt");
        }
    }
    
    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("failed to set hkdf info");
        }
    }
    
    if (EVP_PKEY_derive(pctx, output.data(), &output_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("failed to derive key");
    }
    
    EVP_PKEY_CTX_free(pctx);
    return output;
}

HandshakeKeys KeyDerivation::derive_session_keys(const std::vector<uint8_t>& shared_secret,
                                                const std::string& client_id,
                                                const std::string& server_id) {
    HandshakeKeys keys;
    
    std::vector<uint8_t> salt(32);
    RAND_bytes(salt.data(), salt.size());
    
    std::vector<uint8_t> info_c2s(client_id.begin(), client_id.end());
    info_c2s.insert(info_c2s.end(), server_id.begin(), server_id.end());
    info_c2s.push_back(0x01);
    
    std::vector<uint8_t> info_s2c(server_id.begin(), server_id.end());
    info_s2c.insert(info_s2c.end(), client_id.begin(), client_id.end());
    info_s2c.push_back(0x02);
    
    std::vector<uint8_t> info_handshake = {'h', 'a', 'n', 'd', 's', 'h', 'a', 'k', 'e'};
    
    keys.client_to_server_key = hkdf(shared_secret, salt, info_c2s);
    keys.server_to_client_key = hkdf(shared_secret, salt, info_s2c);
    keys.handshake_key = hkdf(shared_secret, salt, info_handshake);
    
    return keys;
}

std::array<uint8_t, 32> KeyDerivation::derive_data_key(const std::array<uint8_t, 32>& session_key,
                                                      uint64_t packet_sequence) {
    std::vector<uint8_t> input_key(session_key.begin(), session_key.end());
    std::vector<uint8_t> info(8);
    memcpy(info.data(), &packet_sequence, 8);
    
    return hkdf(input_key, {}, info);
}

std::vector<uint8_t> KeyDerivation::generate_random_bytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    if (RAND_bytes(bytes.data(), length) != 1) {
        throw std::runtime_error("failed to generate random bytes");
    }
    return bytes;
}

HandshakeProtocol::HandshakeProtocol(bool is_server) 
    : is_server_(is_server)
    , state_(HandshakeState::INITIAL)
    , timeout_(std::chrono::seconds(30)) {
    handshake_start_ = std::chrono::steady_clock::now();
}

void HandshakeProtocol::initialize_client(const std::string& client_id, const std::string& server_address) {
    client_id_ = client_id;
    server_id_ = server_address;
    generate_client_keypair();
    RAND_bytes(client_random_.data(), client_random_.size());
}

void HandshakeProtocol::initialize_server(const std::string& server_id, const std::vector<uint8_t>&) {
    server_id_ = server_id;
    RAND_bytes(server_random_.data(), server_random_.size());
}

std::vector<uint8_t> HandshakeProtocol::create_client_hello() {
    ClientHello hello;
    hello.protocol_version = 1;
    hello.client_random = client_random_;
    hello.client_id = client_id_;
    hello.supported_ciphers = {0x01};
    hello.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    state_ = HandshakeState::CLIENT_HELLO_SENT;
    return serialize_client_hello(hello);
}

std::vector<uint8_t> HandshakeProtocol::process_client_hello(const std::vector<uint8_t>& data) {
    auto hello = deserialize_client_hello(data);
    client_id_ = hello.client_id;
    client_random_ = hello.client_random;
    
    ServerHello response;
    response.protocol_version = 1;
    response.server_random = server_random_;
    response.server_id = server_id_;
    response.selected_cipher = 0x01;
    response.server_certificate = {};
    response.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    return serialize_server_hello(response);
}

std::vector<uint8_t> HandshakeProtocol::process_server_hello(const std::vector<uint8_t>& data) {
    auto hello = deserialize_server_hello(data);
    server_id_ = hello.server_id;
    server_random_ = hello.server_random;
    
    state_ = HandshakeState::SERVER_HELLO_RECEIVED;
    return create_key_exchange();
}

std::vector<uint8_t> HandshakeProtocol::create_key_exchange() {
    KeyExchange exchange;
    exchange.client_public_key = client_public_key_;
    exchange.client_certificate = {};
    exchange.signature = sign_data(client_public_key_);
    
    state_ = HandshakeState::CLIENT_KEY_EXCHANGE_SENT;
    return serialize_key_exchange(exchange);
}

std::vector<uint8_t> HandshakeProtocol::process_key_exchange(const std::vector<uint8_t>& data) {
    auto exchange = deserialize_key_exchange(data);
    server_public_key_ = exchange.client_public_key;
    
    if (!verify_signature(exchange.client_public_key, exchange.signature)) {
        state_ = HandshakeState::FAILED;
        throw std::runtime_error("key exchange signature verification failed");
    }
    
    calculate_shared_secret();
    session_keys_ = KeyDerivation::derive_session_keys(shared_secret_, client_id_, server_id_);
    
    return create_server_finished();
}

std::vector<uint8_t> HandshakeProtocol::create_server_finished() {
    ServerFinished finished;
    finished.verify_data = KeyDerivation::generate_random_bytes(32);
    finished.session_parameters = {};
    
    state_ = HandshakeState::COMPLETED;
    return serialize_server_finished(finished);
}

bool HandshakeProtocol::process_server_finished(const std::vector<uint8_t>& data) {
    auto finished = deserialize_server_finished(data);
    
    calculate_shared_secret();
    session_keys_ = KeyDerivation::derive_session_keys(shared_secret_, client_id_, server_id_);
    
    state_ = HandshakeState::COMPLETED;
    return true;
}

HandshakeState HandshakeProtocol::get_state() const {
    return state_;
}

bool HandshakeProtocol::is_completed() const {
    return state_ == HandshakeState::COMPLETED;
}

HandshakeKeys HandshakeProtocol::get_session_keys() const {
    if (!is_completed()) {
        throw std::runtime_error("handshake not completed");
    }
    return session_keys_;
}

void HandshakeProtocol::set_timeout(std::chrono::milliseconds timeout) {
    timeout_ = timeout;
}

bool HandshakeProtocol::is_timeout_expired() const {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - handshake_start_) > timeout_;
}

void HandshakeProtocol::generate_client_keypair() {
    client_private_key_ = KeyDerivation::generate_random_bytes(32);
    client_public_key_ = KeyDerivation::generate_random_bytes(32);
}

void HandshakeProtocol::calculate_shared_secret() {
    shared_secret_ = KeyDerivation::generate_random_bytes(32);
}

std::vector<uint8_t> HandshakeProtocol::sign_data(const std::vector<uint8_t>&) {
    return KeyDerivation::generate_random_bytes(64);
}

bool HandshakeProtocol::verify_signature(const std::vector<uint8_t>&, const std::vector<uint8_t>& signature) {
    return signature.size() == 64;
}

std::vector<uint8_t> HandshakeProtocol::serialize_client_hello(const ClientHello& hello) {
    std::vector<uint8_t> data;
    data.reserve(1024);
    
    auto version_bytes = reinterpret_cast<const uint8_t*>(&hello.protocol_version);
    data.insert(data.end(), version_bytes, version_bytes + 4);
    
    data.insert(data.end(), hello.client_random.begin(), hello.client_random.end());
    
    uint32_t id_len = hello.client_id.size();
    auto id_len_bytes = reinterpret_cast<const uint8_t*>(&id_len);
    data.insert(data.end(), id_len_bytes, id_len_bytes + 4);
    data.insert(data.end(), hello.client_id.begin(), hello.client_id.end());
    
    uint32_t cipher_len = hello.supported_ciphers.size();
    auto cipher_len_bytes = reinterpret_cast<const uint8_t*>(&cipher_len);
    data.insert(data.end(), cipher_len_bytes, cipher_len_bytes + 4);
    data.insert(data.end(), hello.supported_ciphers.begin(), hello.supported_ciphers.end());
    
    auto timestamp_bytes = reinterpret_cast<const uint8_t*>(&hello.timestamp);
    data.insert(data.end(), timestamp_bytes, timestamp_bytes + 8);
    
    return data;
}

ClientHello HandshakeProtocol::deserialize_client_hello(const std::vector<uint8_t>& data) {
    ClientHello hello;
    size_t offset = 0;
    
    memcpy(&hello.protocol_version, data.data() + offset, 4);
    offset += 4;
    
    std::copy(data.begin() + offset, data.begin() + offset + 32, hello.client_random.begin());
    offset += 32;
    
    uint32_t id_len;
    memcpy(&id_len, data.data() + offset, 4);
    offset += 4;
    
    hello.client_id.assign(data.begin() + offset, data.begin() + offset + id_len);
    offset += id_len;
    
    uint32_t cipher_len;
    memcpy(&cipher_len, data.data() + offset, 4);
    offset += 4;
    
    hello.supported_ciphers.assign(data.begin() + offset, data.begin() + offset + cipher_len);
    offset += cipher_len;
    
    memcpy(&hello.timestamp, data.data() + offset, 8);
    
    return hello;
}

std::vector<uint8_t> HandshakeProtocol::serialize_server_hello(const ServerHello& hello) {
    std::vector<uint8_t> data;
    data.reserve(1024);
    
    auto version_bytes = reinterpret_cast<const uint8_t*>(&hello.protocol_version);
    data.insert(data.end(), version_bytes, version_bytes + 4);
    
    data.insert(data.end(), hello.server_random.begin(), hello.server_random.end());
    
    uint32_t id_len = hello.server_id.size();
    auto id_len_bytes = reinterpret_cast<const uint8_t*>(&id_len);
    data.insert(data.end(), id_len_bytes, id_len_bytes + 4);
    data.insert(data.end(), hello.server_id.begin(), hello.server_id.end());
    
    data.push_back(hello.selected_cipher);
    
    uint32_t cert_len = hello.server_certificate.size();
    auto cert_len_bytes = reinterpret_cast<const uint8_t*>(&cert_len);
    data.insert(data.end(), cert_len_bytes, cert_len_bytes + 4);
    data.insert(data.end(), hello.server_certificate.begin(), hello.server_certificate.end());
    
    auto timestamp_bytes = reinterpret_cast<const uint8_t*>(&hello.timestamp);
    data.insert(data.end(), timestamp_bytes, timestamp_bytes + 8);
    
    return data;
}

ServerHello HandshakeProtocol::deserialize_server_hello(const std::vector<uint8_t>& data) {
    ServerHello hello;
    size_t offset = 0;
    
    memcpy(&hello.protocol_version, data.data() + offset, 4);
    offset += 4;
    
    std::copy(data.begin() + offset, data.begin() + offset + 32, hello.server_random.begin());
    offset += 32;
    
    uint32_t id_len;
    memcpy(&id_len, data.data() + offset, 4);
    offset += 4;
    
    hello.server_id.assign(data.begin() + offset, data.begin() + offset + id_len);
    offset += id_len;
    
    hello.selected_cipher = data[offset++];
    
    uint32_t cert_len;
    memcpy(&cert_len, data.data() + offset, 4);
    offset += 4;
    
    hello.server_certificate.assign(data.begin() + offset, data.begin() + offset + cert_len);
    offset += cert_len;
    
    memcpy(&hello.timestamp, data.data() + offset, 8);
    
    return hello;
}

std::vector<uint8_t> HandshakeProtocol::serialize_key_exchange(const KeyExchange& exchange) {
    std::vector<uint8_t> data;
    data.reserve(1024);
    
    uint32_t key_len = exchange.client_public_key.size();
    auto key_len_bytes = reinterpret_cast<const uint8_t*>(&key_len);
    data.insert(data.end(), key_len_bytes, key_len_bytes + 4);
    data.insert(data.end(), exchange.client_public_key.begin(), exchange.client_public_key.end());
    
    uint32_t cert_len = exchange.client_certificate.size();
    auto cert_len_bytes = reinterpret_cast<const uint8_t*>(&cert_len);
    data.insert(data.end(), cert_len_bytes, cert_len_bytes + 4);
    data.insert(data.end(), exchange.client_certificate.begin(), exchange.client_certificate.end());
    
    uint32_t sig_len = exchange.signature.size();
    auto sig_len_bytes = reinterpret_cast<const uint8_t*>(&sig_len);
    data.insert(data.end(), sig_len_bytes, sig_len_bytes + 4);
    data.insert(data.end(), exchange.signature.begin(), exchange.signature.end());
    
    return data;
}

KeyExchange HandshakeProtocol::deserialize_key_exchange(const std::vector<uint8_t>& data) {
    KeyExchange exchange;
    size_t offset = 0;
    
    uint32_t key_len;
    memcpy(&key_len, data.data() + offset, 4);
    offset += 4;
    
    exchange.client_public_key.assign(data.begin() + offset, data.begin() + offset + key_len);
    offset += key_len;
    
    uint32_t cert_len;
    memcpy(&cert_len, data.data() + offset, 4);
    offset += 4;
    
    exchange.client_certificate.assign(data.begin() + offset, data.begin() + offset + cert_len);
    offset += cert_len;
    
    uint32_t sig_len;
    memcpy(&sig_len, data.data() + offset, 4);
    offset += 4;
    
    exchange.signature.assign(data.begin() + offset, data.begin() + offset + sig_len);
    
    return exchange;
}

std::vector<uint8_t> HandshakeProtocol::serialize_server_finished(const ServerFinished& finished) {
    std::vector<uint8_t> data;
    data.reserve(512);
    
    uint32_t verify_len = finished.verify_data.size();
    auto verify_len_bytes = reinterpret_cast<const uint8_t*>(&verify_len);
    data.insert(data.end(), verify_len_bytes, verify_len_bytes + 4);
    data.insert(data.end(), finished.verify_data.begin(), finished.verify_data.end());
    
    uint32_t params_len = finished.session_parameters.size();
    auto params_len_bytes = reinterpret_cast<const uint8_t*>(&params_len);
    data.insert(data.end(), params_len_bytes, params_len_bytes + 4);
    data.insert(data.end(), finished.session_parameters.begin(), finished.session_parameters.end());
    
    return data;
}

ServerFinished HandshakeProtocol::deserialize_server_finished(const std::vector<uint8_t>& data) {
    ServerFinished finished;
    size_t offset = 0;
    
    uint32_t verify_len;
    memcpy(&verify_len, data.data() + offset, 4);
    offset += 4;
    
    finished.verify_data.assign(data.begin() + offset, data.begin() + offset + verify_len);
    offset += verify_len;
    
    uint32_t params_len;
    memcpy(&params_len, data.data() + offset, 4);
    offset += 4;
    
    finished.session_parameters.assign(data.begin() + offset, data.begin() + offset + params_len);
    
    return finished;
}

AntiReplayProtection::AntiReplayProtection(size_t window_size) 
    : window_size_(window_size)
    , highest_sequence_(0)
    , received_bitmap_(window_size, false) {
}

bool AntiReplayProtection::is_sequence_valid(uint64_t sequence_number) {
    if (sequence_number == 0) {
        return false;
    }
    
    if (sequence_number > highest_sequence_) {
        return true;
    }
    
    if (sequence_number <= highest_sequence_ - window_size_) {
        return false;
    }
    
    size_t index = get_bitmap_index(sequence_number);
    return !received_bitmap_[index];
}

void AntiReplayProtection::mark_sequence_received(uint64_t sequence_number) {
    if (sequence_number > highest_sequence_) {
        advance_window(sequence_number);
        highest_sequence_ = sequence_number;
    }
    
    if (is_in_window(sequence_number)) {
        size_t index = get_bitmap_index(sequence_number);
        received_bitmap_[index] = true;
    }
}

void AntiReplayProtection::reset_window(uint64_t new_base_sequence) {
    highest_sequence_ = new_base_sequence;
    std::fill(received_bitmap_.begin(), received_bitmap_.end(), false);
}

size_t AntiReplayProtection::get_window_size() const {
    return window_size_;
}

uint64_t AntiReplayProtection::get_last_valid_sequence() const {
    return highest_sequence_;
}

bool AntiReplayProtection::is_in_window(uint64_t sequence_number) const {
    return sequence_number > highest_sequence_ - window_size_ && sequence_number <= highest_sequence_;
}

size_t AntiReplayProtection::get_bitmap_index(uint64_t sequence_number) const {
    return (highest_sequence_ - sequence_number) % window_size_;
}

void AntiReplayProtection::advance_window(uint64_t new_sequence) {
    uint64_t advance_count = new_sequence - highest_sequence_;
    if (advance_count >= window_size_) {
        std::fill(received_bitmap_.begin(), received_bitmap_.end(), false);
    } else {
        std::rotate(received_bitmap_.begin(), 
                   received_bitmap_.begin() + advance_count, 
                   received_bitmap_.end());
        std::fill(received_bitmap_.end() - advance_count, received_bitmap_.end(), false);
    }
}

SecurityManager::SecurityManager() 
    : is_server_(false)
    , packets_encrypted_(0) {
}

void SecurityManager::initialize(bool is_server, const std::string& identity) {
    is_server_ = is_server;
    identity_ = identity;
    
    handshake_ = std::make_unique<HandshakeProtocol>(is_server);
    replay_protection_ = std::make_unique<AntiReplayProtection>();
    
    if (is_server) {
        handshake_->initialize_server(identity, {});
    }
    
    last_key_rotation_ = std::chrono::steady_clock::now();
}

bool SecurityManager::start_handshake(const std::string& peer_identity) {
    if (!is_server_) {
        handshake_->initialize_client(identity_, peer_identity);
        return true;
    }
    return false;
}

std::vector<uint8_t> SecurityManager::process_handshake_message(const std::vector<uint8_t>& message) {
    if (!handshake_) {
        throw std::runtime_error("handshake not initialized");
    }
    
    if (handshake_->is_timeout_expired()) {
        throw std::runtime_error("handshake timeout expired");
    }
    
    switch (handshake_->get_state()) {
        case HandshakeState::INITIAL:
            if (is_server_) {
                return handshake_->process_client_hello(message);
            } else {
                return handshake_->create_client_hello();
            }
        case HandshakeState::CLIENT_HELLO_SENT:
            return handshake_->process_server_hello(message);
        case HandshakeState::SERVER_HELLO_RECEIVED:
            return {};
        case HandshakeState::CLIENT_KEY_EXCHANGE_SENT:
            handshake_->process_server_finished(message);
            current_keys_ = handshake_->get_session_keys();
            data_cipher_ = std::make_unique<ChaCha20Poly1305>(current_keys_.client_to_server_key);
            return {};
        default:
            if (is_server_ && handshake_->get_state() == HandshakeState::INITIAL) {
                auto response = handshake_->process_key_exchange(message);
                current_keys_ = handshake_->get_session_keys();
                data_cipher_ = std::make_unique<ChaCha20Poly1305>(current_keys_.server_to_client_key);
                return response;
            }
            break;
    }
    
    return {};
}

bool SecurityManager::is_handshake_complete() const {
    return handshake_ && handshake_->is_completed();
}

std::vector<uint8_t> SecurityManager::encrypt_data(const std::vector<uint8_t>& plaintext, uint64_t sequence_number) {
    if (!is_handshake_complete() || !data_cipher_) {
        throw std::runtime_error("handshake not completed or cipher not available");
    }
    
    derive_packet_keys(sequence_number);
    auto nonce = data_cipher_->generate_nonce();
    packets_encrypted_++;
    
    return data_cipher_->encrypt(plaintext, nonce);
}

std::vector<uint8_t> SecurityManager::decrypt_data(const std::vector<uint8_t>& ciphertext, uint64_t sequence_number) {
    if (!is_handshake_complete() || !data_cipher_) {
        throw std::runtime_error("handshake not completed or cipher not available");
    }
    
    if (!validate_sequence_number(sequence_number)) {
        throw std::runtime_error("invalid sequence number - possible replay attack");
    }
    
    derive_packet_keys(sequence_number);
    
    std::array<uint8_t, ChaCha20Poly1305::NONCE_SIZE> nonce;
    if (ciphertext.size() < nonce.size()) {
        throw std::runtime_error("ciphertext too short to contain nonce");
    }
    
    std::copy(ciphertext.begin(), ciphertext.begin() + nonce.size(), nonce.begin());
    std::vector<uint8_t> actual_ciphertext(ciphertext.begin() + nonce.size(), ciphertext.end());
    
    mark_sequence_processed(sequence_number);
    return data_cipher_->decrypt(actual_ciphertext, nonce);
}

bool SecurityManager::validate_sequence_number(uint64_t sequence_number) {
    return replay_protection_->is_sequence_valid(sequence_number);
}

void SecurityManager::mark_sequence_processed(uint64_t sequence_number) {
    replay_protection_->mark_sequence_received(sequence_number);
}

void SecurityManager::rotate_keys() {
    if (!is_handshake_complete()) {
        return;
    }
    
    auto new_key = KeyDerivation::derive_data_key(current_keys_.client_to_server_key, packets_encrypted_);
    data_cipher_->set_key(new_key);
    last_key_rotation_ = std::chrono::steady_clock::now();
    packets_encrypted_ = 0;
}

bool SecurityManager::is_key_rotation_needed() const {
    return should_rotate_keys();
}

void SecurityManager::set_certificate_validator(std::shared_ptr<CertificateValidator> validator) {
    cert_validator_ = std::move(validator);
}

void SecurityManager::derive_packet_keys(uint64_t sequence_number) {
    if (sequence_number % 1000 == 0) {
        auto packet_key = KeyDerivation::derive_data_key(current_keys_.client_to_server_key, sequence_number);
        data_cipher_->set_key(packet_key);
    }
}

bool SecurityManager::should_rotate_keys() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::hours>(now - last_key_rotation_);
    return elapsed.count() >= 24 || packets_encrypted_ >= 1000000;
}

bool SecurityManager::verify_packet_integrity(const std::vector<uint8_t>& packet_data, const std::string& client_id) {
    return !packet_data.empty() && !client_id.empty();
}

bool SecurityManager::encrypt_packet(const std::vector<uint8_t>& packet_data, const std::string&, std::vector<uint8_t>& encrypted_data) {
    encrypted_data = encrypt_data(packet_data, 0);
    return !encrypted_data.empty();
}

}
