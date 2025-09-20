#!/bin/bash

set -euo pipefail

SERVICE_NAME="cspnetwork"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/cspnetwork"
LOG_DIR="/var/log/cspnetwork"
DATA_DIR="/var/lib/cspnetwork"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "error: this script must be run as root (use sudo)"
        exit 1
    fi
}

stop_and_disable_service() {
    echo "stopping and disabling service..."
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME"
    fi
    if systemctl is-enabled --quiet "$SERVICE_NAME"; then
        systemctl disable "$SERVICE_NAME"
    fi
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
}

remove_binary() {
    echo "removing binary..."
    rm -f "$INSTALL_DIR/cspnetwork"
}

remove_user() {
    if id "$SERVICE_NAME" &>/dev/null; then
        echo "removing system user: $SERVICE_NAME"
        userdel "$SERVICE_NAME" 2>/dev/null || true
    fi
}

remove_directories() {
    echo "removing directories..."
    read -p "remove configuration directory $CONFIG_DIR? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
    fi
    
    read -p "remove log directory $LOG_DIR? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$LOG_DIR"
    fi
    
    read -p "remove data directory $DATA_DIR? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$DATA_DIR"
    fi
}

main() {
    echo "uninstalling cspnetwork service..."
    
    check_root
    stop_and_disable_service
    remove_binary
    remove_user
    remove_directories
    
    echo
    echo "uninstallation completed!"
}

main "$@"
