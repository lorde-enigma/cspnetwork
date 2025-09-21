#pragma once

#include <string>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace infrastructure {

class Logger {
public:
    enum Level {
        DEBUG,
        INFO,
        WARN,
        ERROR
    };

    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    void debug(const std::string& message) {
        log(DEBUG, message);
    }

    void info(const std::string& message) {
        log(INFO, message);
    }

    void warn(const std::string& message) {
        log(WARN, message);
    }

    void error(const std::string& message) {
        log(ERROR, message);
    }

    void setLevel(Level level) {
        currentLevel = level;
    }

private:
    Level currentLevel = INFO;

    void log(Level level, const std::string& message) {
        if (level < currentLevel) return;

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        
        std::string levelStr;
        switch (level) {
            case DEBUG: levelStr = "DEBUG"; break;
            case INFO:  levelStr = "INFO";  break;
            case WARN:  levelStr = "WARN";  break;
            case ERROR: levelStr = "ERROR"; break;
        }
        
        std::cout << "[" << ss.str() << "] [" << levelStr << "] " << message << std::endl;
    }
};

}
