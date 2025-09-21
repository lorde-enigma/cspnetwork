#include "infrastructure/crc32.h"

namespace seeded_vpn::infrastructure {

uint32_t CRC32::crc_table_[256];
bool CRC32::table_initialized_ = false;

void CRC32::initialize_table() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc_table_[i] = crc;
    }
    table_initialized_ = true;
}

uint32_t CRC32::calculate(const uint8_t* data, size_t length) {
    if (!table_initialized_) {
        initialize_table();
    }
    
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc = crc_table_[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

uint32_t CRC32::calculate(const std::vector<uint8_t>& data) {
    return calculate(data.data(), data.size());
}

}
