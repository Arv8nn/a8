#!/bin/bash

# Configuration
INSTALL_DIR="${HOME}/serv00-mtg"
CONFIG_FILE="${INSTALL_DIR}/config.json"
MTG_VERSION="v2.1.7"
MTG_URL="https://github.com/9seconds/mtg/releases/download/${MTG_VERSION}/mtg-${MTG_VERSION}-linux-amd64-static.tar.gz"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${RED}Invalid port! Must be between 1 and 65535${NC}"
        return 1
    fi
    return 0
}

check_port_availability() {
    local port=$1
    if ss -tuln | grep -q ":$port "; then
        echo -e "${RED}Port $port is already in use!${NC}"
        return 1
    fi
    return 0
}

get_port_input() {
    while true; do
        read -p "Enter port number [or press Enter for random port]: " port_input
        if [ -z "$port_input" ]; then
            port=$(get_random_port)
            echo -e "${YELLOW}Using random port: $port${NC}"
            return 0
        fi
        
        if validate_port "$port_input"; then
            if check_port_availability "$port_input"; then
                port=$port_input
                return 0
            fi
        fi
    done
}

install_mtg() {
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR" || exit 1

    if [ ! -f "${INSTALL_DIR}/mtg" ]; then
        if ! download_mtg; then
            return 1
        fi
    fi

    local reconfigure="n"
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}Current configuration:${NC}"
        jq . "$CONFIG_FILE"
        read -r -p "Reconfigure? [y/N]: " reconfigure
        reconfigure=${reconfigure:-n}
    fi

    if [ "$reconfigure" != "y" ] && [ -f "$CONFIG_FILE" ]; then
        return 0
    fi

    # Get user input
    get_port_input
    local hostname
    hostname=$(hostname).serv00.com
    local secret
    secret=$("${INSTALL_DIR}/mtg" generate-secret -c 32 --hex "$hostname")

    # Create config
    jq -n \
        --arg secret "$secret" \
        --arg port "$port" \
        --arg host "$hostname" \
        '{
            secret: $secret,
            port: $port|tonumber,
            host: $host
        }' > "$CONFIG_FILE"

    echo -e "${GREEN}Configuration created:${NC}"
    jq . "$CONFIG_FILE"
}

# بقیه توابع بدون تغییر (همان نسخه قبلی)

main() {
    check_dependencies
    
    case "$1" in
        install)
            install_mtg
            ;;
        # ... سایر موارد بدون تغییر
    esac
}

main "$@"
