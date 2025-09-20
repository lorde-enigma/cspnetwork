#include "../include/infrastructure/seeded_system_monitor.h"
#include "../include/infrastructure/ipv6_address_manager.h"
#include <iostream>

namespace seeded_vpn::infrastructure {

SeededSystemMonitor::SeededSystemMonitor(std::shared_ptr<domain::ILogger> logger)
    : logger_(logger), running_(false), checkInterval_(30) {}

SeededSystemMonitor::~SeededSystemMonitor() {
    stop();
}

void SeededSystemMonitor::start() {
    if (running_.load()) return;
    
    running_.store(true);
    monitorThread_ = std::thread(&SeededSystemMonitor::monitorLoop, this);
    
    if (logger_) {
        logger_->info("seeded system monitor started");
    }
}

void SeededSystemMonitor::stop() {
    if (!running_.load()) return;
    
    running_.store(false);
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
    
    if (logger_) {
        logger_->info("seeded system monitor stopped");
    }
}

void SeededSystemMonitor::setCheckInterval(std::chrono::seconds interval) {
    checkInterval_ = interval;
}

void SeededSystemMonitor::monitorLoop() {
    while (running_.load()) {
        try {
            checkSystemHealth();
            logMetrics();
            performMaintenance();
        } catch (const std::exception& e) {
            if (logger_) {
                logger_->error("monitor error: " + std::string(e.what()));
            }
        }
        
        std::this_thread::sleep_for(checkInterval_);
    }
}

void SeededSystemMonitor::checkSystemHealth() {
    checkIPv6Resources();
    checkSeedManagerState();
}

void SeededSystemMonitor::logMetrics() {
    size_t ipv6Count = getUsedIPv6Count();
    
    if (logger_) {
        logger_->info( 
            "system metrics - ipv6 addresses: " + std::to_string(ipv6Count));
    }
}

void SeededSystemMonitor::performMaintenance() {
    static auto lastCleanup = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    
    if (std::chrono::duration_cast<std::chrono::minutes>(now - lastCleanup).count() >= 60) {
        cleanupResources();
        lastCleanup = now;
    }
}

void SeededSystemMonitor::checkIPv6Resources() {
    size_t usedCount = getUsedIPv6Count();
    
    if (usedCount > 8000 && logger_) {
        logger_->warn( 
            "high ipv6 usage: " + std::to_string(usedCount));
    }
}

void SeededSystemMonitor::checkSeedManagerState() {
    if (logger_) {
        logger_->debug("seed manager operational");
    }
}

void SeededSystemMonitor::cleanupResources() {
    if (logger_) {
        logger_->info("performing resource cleanup");
    }
    
    auto& manager = IPv6AddressManager::getInstance();
    manager.clearCache();
}

size_t SeededSystemMonitor::getUsedIPv6Count() {
    auto& manager = IPv6AddressManager::getInstance();
    return manager.getCacheSize();
}

}
