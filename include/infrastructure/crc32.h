#pragma once

#include <cstdint>
#include <vector>

namespace seeded_vpn::infrastructure {

class CRC32 {
public:
    static uint32_t calculate(const uint8_t* data, size_t length);
    static uint32_t calculate(const std::vector<uint8_t>& data);
    
private:
    static uint32_t crc_table_[256];
    static bool table_initialized_;
    static void initialize_table();
};

}
