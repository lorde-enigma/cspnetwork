#pragma once

#include <string>
#include <vector>
#include <memory>
#include <map>
#include <iostream>

namespace SeededVPN::Presentation {

class CLICommand {
public:
    virtual ~CLICommand() = default;
    virtual void execute(const std::vector<std::string>& args) = 0;
    virtual std::string getDescription() const = 0;
    virtual std::string getUsage() const = 0;
};

class StatusCommand : public CLICommand {
public:
    void execute(const std::vector<std::string>& args) override;
    std::string getDescription() const override;
    std::string getUsage() const override;
};

class ConnectionsCommand : public CLICommand {
public:
    void execute(const std::vector<std::string>& args) override;
    std::string getDescription() const override;
    std::string getUsage() const override;
};

class AddressPoolCommand : public CLICommand {
public:
    void execute(const std::vector<std::string>& args) override;
    std::string getDescription() const override;
    std::string getUsage() const override;
};

class ConfigCommand : public CLICommand {
public:
    void execute(const std::vector<std::string>& args) override;
    std::string getDescription() const override;
    std::string getUsage() const override;
};

class CLIManager {
    std::map<std::string, std::unique_ptr<CLICommand>> commands;
    
public:
    CLIManager();
    ~CLIManager() = default;
    
    bool executeCommand(const std::string& commandLine);
    void showHelp();
    void showVersion();
    
private:
    std::vector<std::string> parseCommandLine(const std::string& line);
    void registerCommand(const std::string& name, std::unique_ptr<CLICommand> command);
};

}
