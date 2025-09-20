#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
SERVICE_FILE="$PROJECT_ROOT/services/cspnetwork.service"

SERVICE_NAME="cspnetwork"
BINARY_NAME="cspnetwork"
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

create_user() {
    if ! id "$SERVICE_NAME" &>/dev/null; then
        echo "creating system user: $SERVICE_NAME"
        useradd --system --shell /bin/false --home-dir "$DATA_DIR" --create-home "$SERVICE_NAME"
    else
        echo "user $SERVICE_NAME already exists"
    fi
}

create_directories() {
    echo "creating directories..."
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    chown "$SERVICE_NAME:$SERVICE_NAME" "$LOG_DIR" "$DATA_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 750 "$LOG_DIR" "$DATA_DIR"
}

install_binary() {
    if [[ ! -f "$BUILD_DIR/$BINARY_NAME" ]]; then
        echo "error: binary not found at $BUILD_DIR/$BINARY_NAME"
        echo "please build the project first: cmake --build build --target cspnetwork"
        exit 1
    fi
    
    echo "installing binary to $INSTALL_DIR/cspnetwork"
    cp "$BUILD_DIR/$BINARY_NAME" "$INSTALL_DIR/cspnetwork"
    chmod 755 "$INSTALL_DIR/cspnetwork"
    chown root:root "$INSTALL_DIR/cspnetwork"
}

install_service() {
    echo "installing systemd service..."
    cp "$SERVICE_FILE" "/etc/systemd/system/"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
}

create_default_config() {
    local config_file="$CONFIG_DIR/config.yaml"
    if [[ ! -f "$config_file" ]]; then
        echo "creating default configuration..."
        cat > "$config_file" << 'EOF'
server:
  port: 8080
  threads: 4
  max_connections: 1000

monitoring:
  log_directory: "/var/log/cspnetwork"
  log_level: "INFO"
  metrics_enabled: true

security:
  enable_tls: true
  cipher_suite: "ECDHE-RSA-AES256-GCM-SHA384"
  
networking:
  interface: "csp0"
  ipv6_prefix: "2001:db8:csp::/48"
EOF
        chmod 640 "$config_file"
        chown root:"$SERVICE_NAME" "$config_file"
    else
        echo "configuration file already exists: $config_file"
    fi
}

main() {
    echo "installing cspnetwork service..."
    
    check_root
    create_user
    create_directories
    install_binary
    create_default_config
    install_service
    
    echo
    echo "installation completed successfully!"
    echo
    echo "next steps:"
    echo "  1. review configuration: $CONFIG_DIR/config.yaml"
    echo "  2. start service: systemctl start $SERVICE_NAME"
    echo "  3. check status: systemctl status $SERVICE_NAME"
    echo "  4. view logs: journalctl -u $SERVICE_NAME -f"
    echo
}

main "$@"
