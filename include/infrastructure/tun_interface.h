#pragma once

#include <string>
#include <memory>
#include <functional>
#include <vector>

namespace seeded_vpn::infrastructure {

struct TunConfig {
    std::string device_name;
    std::string local_ip;
    std::string remote_ip;
    std::string netmask;
    uint16_t mtu;
    bool persistent;
};

class TunInterface {
public:
    using PacketCallback = std::function<void(const std::vector<uint8_t>&)>;

    TunInterface();
    ~TunInterface();

    bool create_tun(const TunConfig& config);
    bool configure_interface(const TunConfig& config);
    void destroy_tun();
    
    bool is_active() const;
    int get_fd() const;
    std::string get_device_name() const;
    
    void set_packet_callback(PacketCallback callback);
    void start_packet_loop();
    void stop_packet_loop();
    
    bool send_packet(const std::vector<uint8_t>& packet);
    bool add_route(const std::string& network, const std::string& gateway);
    bool remove_route(const std::string& network);

private:
    std::unique_ptr<class TunInterfaceImpl> impl_;
};

}
