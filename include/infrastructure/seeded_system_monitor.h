#pragma once

#include "../domain/entities.h"
#include <memory>
#include <thread>
#include <atomic>
#include <chrono>

namespace seeded_vpn::infrastructure {

class SeededSystemMonitor {
public:
    explicit SeededSystemMonitor(std::shared_ptr<domain::Logger> logger);
    ~SeededSystemMonitor();

    void start();
    void stop();
    
    void setCheckInterval(std::chrono::seconds interval);

private:
    void monitorLoop();
    void checkSystemHealth();
    void logMetrics();
    void performMaintenance();
    
    void checkIPv6Resources();
    void checkSeedManagerState();
    void cleanupResources();
    
    size_t getUsedIPv6Count();
    
    std::shared_ptr<domain::Logger> logger_;
    std::atomic<bool> running_;
    std::thread monitorThread_;
    std::chrono::seconds checkInterval_;
};

}
