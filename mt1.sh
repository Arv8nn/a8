#!/bin/bash

# Configuration
INSTALL_DIR="$HOME/tg-proxy"
BIN_PATH="$INSTALL_DIR/mtg"
CONFIG_FILE="$INSTALL_DIR/config.cfg"
VERSION="v2.1.7"
BIN_URL="https://github.com/9seconds/mtg/releases/download/${VERSION}/mtg-${VERSION}-freebsd-amd64.tar.gz"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Check if running as root
check_root() {
    if [ "$(id -u)" -eq 0 ]; then
        echo -e "${RED}Do not run this script as root!${NC}"
        exit 1
    fi
}

# Generate random port
random_port() {
    echo $((RANDOM % 55536 + 10000))
}

# Validate port input
validate_port() {
    local port=$1
    [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 -a "$port" -le 65535 ]
}

# Check port availability using netstat (alternative to ss)
port_available() {
    local port=$1
    ! netstat -tuln | grep -q ":$port\b"
}

# Generate secret key
generate_secret() {
    dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx1 | tr -d ' '
}

# Download mtg binary
download_binary() {
    echo -e "${YELLOW}Downloading mtg binary...${NC}"
    temp_file=$(mktemp)

    if ! curl -sL -o "$temp_file" "$BIN_URL"; then
        echo -e "${RED}Failed to download file!${NC}"
        rm -f "$temp_file"
        return 1
    fi

    if file "$temp_file" | grep -q "gzip compressed data"; then
        tar xzf "$temp_file" -C "$INSTALL_DIR" --strip-components=1
        rm -f "$temp_file"
        chmod +x "$BIN_PATH"
        return 0
    else
        echo -e "${RED}Downloaded file is not a valid gzip archive!${NC}"
        echo -e "${YELLOW}This could be due to:"
        echo -e "1. Network issues"
        echo -e "2. GitHub rate limiting"
        echo -e "3. Invalid download URL${NC}"
        rm -f "$temp_file"
        return 1
    fi
}

# Show connection info (basic info to display after installation)
show_connection_info() {
    # Generate proxy link for Telegram (MTProto proxy)
    proxy_link="tg://proxy?server=$hostname&port=$port&secret=$secret"
    
    echo -e "\n${GREEN}Your Telegram proxy is now set up with the following configuration:${NC}"
    echo "Host: $hostname"
    echo "Port: $port"
    echo "Secret: $secret"
    echo -e "\n${GREEN}Connection Link for Telegram:${NC} $proxy_link"
}

# Install Proxy
install_proxy() {
    check_root
    mkdir -p "$INSTALL_DIR"

    # Download the mtg binary
    if ! download_binary; then
        exit 1
    fi

    # Get hostname
    public_ip=$(curl -s ifconfig.me)
    read -p "Enter hostname/IP [default: $public_ip]: " hostname
    hostname=${hostname:-$public_ip}

    # Get port
    while true; do
        default_port=$(random_port)
        read -p "Enter port [default: $default_port]: " port
        port=${port:-$default_port}

        if validate_port "$port"; then
            if port_available "$port"; then
                break
            else
                echo -e "${RED}Port $port is already in use!${NC}"
            fi
        else
            echo -e "${RED}Invalid port number! Please enter a number between 1 and 65535.${NC}"
        fi
    done

    # Generate secret key
    secret=$(generate_secret)

    # Save config
    echo "HOST=$hostname" > "$CONFIG_FILE"
    echo "PORT=$port" >> "$CONFIG_FILE"
    echo "SECRET=$secret" >> "$CONFIG_FILE"

    echo -e "\n${GREEN}Installation complete!${NC}"
    show_connection_info
}

# Start installation
install_proxy
