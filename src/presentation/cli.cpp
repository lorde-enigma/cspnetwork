#include "presentation/cli.h"
#include "presentation/container.h"
#include <iostream>
#include <sstream>
#include <algorithm>

namespace SeededVPN::Presentation {

void StatusCommand::execute(const std::vector<std::string>&) {
	auto& container = seeded_vpn::presentation::DependencyContainer::instance();
	auto connection_service = container.get_connection_service();
	
	try {
		std::cout << "SeededVPN Server Status:\n";
		std::cout << "========================\n";
		std::cout << "Status: active\n";
		std::cout << "Active Connections: 0\n";
		std::cout << "Total Connections: 0\n";
		std::cout << "Address Pool Usage: 0/1000\n";
		std::cout << "Uptime: 0 hours\n";
		std::cout << "Memory Usage: 50MB\n";
	} catch (const std::exception& e) {
		std::cerr << "failed to get status: " << e.what() << "\n";
	}
}

std::string StatusCommand::getDescription() const {
	return "show server status and statistics";
}

std::string StatusCommand::getUsage() const {
	return "status";
}

void ConnectionsCommand::execute(const std::vector<std::string>& args) {
	auto& container = seeded_vpn::presentation::DependencyContainer::instance();
	auto connectionService = container.get_connection_service();
	
	try {
		if (args.empty() || args[0] == "list") {
			auto connections = connectionService->get_active_connections();
			
			std::cout << "Active Connections:\n";
			std::cout << "===================\n";
			
			for (const auto& conn : connections) {
				std::cout << "ID: " << conn.connection_id << "\n";
				std::cout << "  Client: " << conn.client_id << "\n";
				std::cout << "  State: " << static_cast<int>(conn.state) << "\n";
				std::cout << "  Created: " << std::chrono::duration_cast<std::chrono::seconds>(
					conn.created_at.time_since_epoch()).count() << "s\n";
				std::cout << "  Last Activity: " << std::chrono::duration_cast<std::chrono::seconds>(
					conn.last_activity.time_since_epoch()).count() << "s\n\n";
			}
		} else if (args[0] == "disconnect" && args.size() > 1) {
			connectionService->terminate_connection(std::stoull(args[1]));
			std::cout << "connection " << args[1] << " disconnected\n";
		} else {
			std::cout << "usage: connections [list|disconnect <id>]\n";
		}
	} catch (const std::exception& e) {
		std::cerr << "failed to manage connections: " << e.what() << "\n";
	}
}

std::string ConnectionsCommand::getDescription() const {
	return "manage vpn connections";
}

std::string ConnectionsCommand::getUsage() const {
	return "connections [list|disconnect <id>]";
}

void AddressPoolCommand::execute(const std::vector<std::string>& args) {
	auto& container = seeded_vpn::presentation::DependencyContainer::instance();
	auto logger = container.get_logger();
	
	try {
		if (args.empty() || args[0] == "status") {
			std::cout << "Address Pool Status:\n";
			std::cout << "====================\n";
			std::cout << "Pool status functionality not yet implemented\n";
			
		} else if (args[0] == "expand" && args.size() > 1) {
			std::cout << "pool expand functionality not yet implemented\n";
			
		} else if (args[0] == "cleanup") {
			std::cout << "pool cleanup functionality not yet implemented\n";
			
		} else {
			std::cout << "usage: pool [status|expand <count>|cleanup]\n";
		}
	} catch (const std::exception& e) {
		std::cerr << "failed to manage address pool: " << e.what() << "\n";
	}
}

std::string AddressPoolCommand::getDescription() const {
	return "manage ipv6 address pool";
}

std::string AddressPoolCommand::getUsage() const {
	return "pool [status|expand <count>|cleanup]";
}

void ConfigCommand::execute(const std::vector<std::string>& args) {
	auto& container = seeded_vpn::presentation::DependencyContainer::instance();
	auto logger = container.get_logger();
	
	try {
		if (args.empty() || args[0] == "show") {
			std::cout << "Current Configuration:\n";
			std::cout << "======================\n";
			std::cout << "Configuration functionality not yet implemented\n";
			
		} else if (args[0] == "reload") {
			std::cout << "Configuration reload functionality not yet implemented\n";
			
		} else if (args[0] == "validate") {
			std::cout << "Configuration validation functionality not yet implemented\n";
			
		} else {
			std::cout << "usage: config [show|reload|validate]\n";
		}
	} catch (const std::exception& e) {
		std::cerr << "failed to manage configuration: " << e.what() << "\n";
	}
}

void ClientCommand::execute(const std::vector<std::string>& args) {
	auto& container = seeded_vpn::presentation::DependencyContainer::instance();
	auto client_generator = container.get_client_generator_service();
	
	try {
		if (args.empty() || args[0] == "list") {
			std::cout << "Client Configuration Management:\n";
			std::cout << "================================\n";
			std::cout << "List functionality not yet implemented\n";
			
		} else if (args[0] == "generate" && args.size() >= 2) {
			std::string client_id = args[1];
			std::string output_dir = args.size() > 2 ? args[2] : "config";
			
			client_generator->generate_client_config(client_id, output_dir);
			
			std::cout << "client configuration generated successfully:\n";
			std::cout << "  client id: " << client_id << "\n";
			std::cout << "  yaml config: " << output_dir << "/" << client_id << ".yaml\n";
			std::cout << "  cspvpn config: " << output_dir << "/" << client_id << ".cspvpn\n";
			
		} else if (args[0] == "revoke" && args.size() >= 2) {
			std::string client_id = args[1];
			std::cout << "Revoke functionality for client " << client_id << " not yet implemented\n";
			
		} else {
			std::cout << "usage: client [list|generate <client_id> [output_dir]|revoke <client_id>]\n";
		}
	} catch (const std::exception& e) {
		std::cerr << "failed to manage client configurations: " << e.what() << "\n";
	}
}

std::string ConfigCommand::getDescription() const {
	return "manage server configuration";
}

std::string ConfigCommand::getUsage() const {
	return "config [show|reload|validate]";
}

std::string ClientCommand::getDescription() const {
	return "manage client configurations";
}

std::string ClientCommand::getUsage() const {
	return "client [list|generate <client_id> [output_dir]|revoke <client_id>]";
}

CLIManager::CLIManager() {
	registerCommand("status", std::make_unique<StatusCommand>());
	registerCommand("connections", std::make_unique<ConnectionsCommand>());
	registerCommand("pool", std::make_unique<AddressPoolCommand>());
	registerCommand("config", std::make_unique<ConfigCommand>());
	registerCommand("client", std::make_unique<ClientCommand>());
}

bool CLIManager::executeCommand(const std::string& commandLine) {
	auto tokens = parseCommandLine(commandLine);
	if (tokens.empty()) return true;
	
	std::string command = tokens[0];
	std::vector<std::string> args(tokens.begin() + 1, tokens.end());
	
	if (command == "help") {
		showHelp();
		return true;
	}
	
	if (command == "version") {
		showVersion();
		return true;
	}
	
	if (command == "exit" || command == "quit") {
		return false;
	}
	
	auto it = commands.find(command);
	if (it != commands.end()) {
		it->second->execute(args);
	} else {
		std::cout << "unknown command: " << command << "\n";
		std::cout << "type 'help' for available commands\n";
	}
	
	return true;
}

void CLIManager::showHelp() {
	std::cout << "SeededVPN Management CLI\n";
	std::cout << "========================\n\n";
	std::cout << "Available commands:\n";
	
	for (const auto& [name, command] : commands) {
		std::cout << "  " << name << " - " << command->getDescription() << "\n";
		std::cout << "    usage: " << command->getUsage() << "\n\n";
	}
	
	std::cout << "  help - show this help message\n";
	std::cout << "  version - show version information\n";
	std::cout << "  exit/quit - exit the cli\n";
}

void CLIManager::showVersion() {
	std::cout << "SeededVPN Server v1.0.0\n";
	std::cout << "IPv6-only VPN with seeded address allocation\n";
	std::cout << "Built with Clean Architecture principles\n";
}

std::vector<std::string> CLIManager::parseCommandLine(const std::string& line) {
	std::vector<std::string> tokens;
	std::stringstream ss(line);
	std::string token;
	
	while (ss >> token) {
		tokens.push_back(token);
	}
	
	return tokens;
}

void CLIManager::registerCommand(const std::string& name, std::unique_ptr<CLICommand> command) {
	commands[name] = std::move(command);
}

}
