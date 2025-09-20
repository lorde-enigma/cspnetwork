#include "../include/infrastructure/tun_interface.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <cstring>

namespace seeded_vpn::infrastructure {

class TunInterfaceImpl {
public:
    TunInterfaceImpl() : fd_(-1), running_(false) {}
    
    ~TunInterfaceImpl() {
        destroy_tun();
    }
    
    bool create_tun(const TunConfig& config) {
        fd_ = open("/dev/net/tun", O_RDWR);
        if (fd_ < 0) {
            std::cerr << "failed to open /dev/net/tun" << std::endl;
            return false;
        }
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        
        if (!config.device_name.empty()) {
            strncpy(ifr.ifr_name, config.device_name.c_str(), IFNAMSIZ - 1);
        }
        
        if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
            std::cerr << "failed to create tun interface" << std::endl;
            close(fd_);
            fd_ = -1;
            return false;
        }
        
        device_name_ = ifr.ifr_name;
        config_ = config;
        
        if (!configure_interface(config)) {
            destroy_tun();
            return false;
        }
        
        std::cout << "created tun interface: " << device_name_ << std::endl;
        return true;
    }
    
    bool configure_interface(const TunConfig& config) {
        std::string cmd;
        
        cmd = "ip link set dev " + device_name_ + " up";
        if (system(cmd.c_str()) != 0) {
            std::cerr << "failed to bring up interface" << std::endl;
            return false;
        }
        
        if (!config.local_ip.empty()) {
            cmd = "ip addr add " + config.local_ip + "/" + config.netmask + " dev " + device_name_;
            if (system(cmd.c_str()) != 0) {
                std::cerr << "failed to set ip address" << std::endl;
                return false;
            }
        }
        
        if (config.mtu > 0) {
            cmd = "ip link set dev " + device_name_ + " mtu " + std::to_string(config.mtu);
            if (system(cmd.c_str()) != 0) {
                std::cerr << "failed to set mtu" << std::endl;
                return false;
            }
        }
        
        return true;
    }
    
    void destroy_tun() {
        stop_packet_loop();
        
        if (fd_ >= 0) {
            if (!device_name_.empty()) {
                std::string cmd = "ip link set dev " + device_name_ + " down";
                system(cmd.c_str());
            }
            close(fd_);
            fd_ = -1;
        }
        device_name_.clear();
    }
    
    bool is_active() const {
        return fd_ >= 0;
    }
    
    int get_fd() const {
        return fd_;
    }
    
    std::string get_device_name() const {
        return device_name_;
    }
    
    void set_packet_callback(TunInterface::PacketCallback callback) {
        packet_callback_ = callback;
    }
    
    void start_packet_loop() {
        if (fd_ < 0 || running_) return;
        
        running_ = true;
        packet_thread_ = std::thread([this]() {
            char buffer[4096];
            while (running_) {
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(fd_, &read_fds);
                
                struct timeval timeout = {1, 0};
                int result = select(fd_ + 1, &read_fds, nullptr, nullptr, &timeout);
                
                if (result > 0 && FD_ISSET(fd_, &read_fds)) {
                    ssize_t len = read(fd_, buffer, sizeof(buffer));
                    if (len > 0 && packet_callback_) {
                        std::vector<uint8_t> packet(buffer, buffer + len);
                        packet_callback_(packet);
                    }
                } else if (result < 0) {
                    break;
                }
            }
        });
    }
    
    void stop_packet_loop() {
        running_ = false;
        if (packet_thread_.joinable()) {
            packet_thread_.join();
        }
    }
    
    bool send_packet(const std::vector<uint8_t>& packet) {
        if (fd_ < 0) return false;
        
        ssize_t written = write(fd_, packet.data(), packet.size());
        return written == static_cast<ssize_t>(packet.size());
    }
    
    bool add_route(const std::string& network, const std::string& gateway) {
        std::string cmd = "ip route add " + network + " via " + gateway + " dev " + device_name_;
        return system(cmd.c_str()) == 0;
    }
    
    bool remove_route(const std::string& network) {
        std::string cmd = "ip route del " + network + " dev " + device_name_;
        return system(cmd.c_str()) == 0;
    }

private:
    int fd_;
    std::string device_name_;
    TunConfig config_;
    std::atomic<bool> running_;
    std::thread packet_thread_;
    TunInterface::PacketCallback packet_callback_;
};

TunInterface::TunInterface() : impl_(std::make_unique<TunInterfaceImpl>()) {}

TunInterface::~TunInterface() = default;

bool TunInterface::create_tun(const TunConfig& config) {
    return impl_->create_tun(config);
}

bool TunInterface::configure_interface(const TunConfig& config) {
    return impl_->configure_interface(config);
}

void TunInterface::destroy_tun() {
    impl_->destroy_tun();
}

bool TunInterface::is_active() const {
    return impl_->is_active();
}

int TunInterface::get_fd() const {
    return impl_->get_fd();
}

std::string TunInterface::get_device_name() const {
    return impl_->get_device_name();
}

void TunInterface::set_packet_callback(PacketCallback callback) {
    impl_->set_packet_callback(callback);
}

void TunInterface::start_packet_loop() {
    impl_->start_packet_loop();
}

void TunInterface::stop_packet_loop() {
    impl_->stop_packet_loop();
}

bool TunInterface::send_packet(const std::vector<uint8_t>& packet) {
    return impl_->send_packet(packet);
}

bool TunInterface::add_route(const std::string& network, const std::string& gateway) {
    return impl_->add_route(network, gateway);
}

bool TunInterface::remove_route(const std::string& network) {
    return impl_->remove_route(network);
}

}
