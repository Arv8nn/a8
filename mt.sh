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

# Dependency check
check_dependencies() {
    local missing=()
    local deps=("jq" "curl" "tar" "ss")
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing dependencies:${NC} ${missing[*]}"
        echo "Install with:"
        echo "sudo apt-get install -y ${missing[*]}"
        exit 1
    fi
}

get_random_port() {
    echo $((RANDOM % 55536 + 10000))
}

download_mtg() {
    echo -e "${YELLOW}Downloading mtg...${NC}"
    if curl -sL "$MTG_URL" | tar xz -C "$INSTALL_DIR" --strip-components=1 --wildcards '*/mtg'; then
        chmod +x "${INSTALL_DIR}/mtg"
        return 0
    else
        echo -e "${RED}Failed to download mtg!${NC}"
        return 1
    fi
}

validate_port() {
    # ... تابع validate_port از کد قبلی
}

check_port_availability() {
    # ... تابع check_port_availability از کد قبلی
}

get_port_input() {
    # ... تابع get_port_input از کد قبلی
}

install_mtg() {
    # ... تابع install_mtg از کد قبلی
}

start_mtg() {
    # ... تابع start_mtg از کد قبلی
}

# ... سایر توابع بدون تغییر

main() {
    check_dependencies  # خط 98 اصلی
    
    case "$1" in
        install)
            install_mtg
            ;;
        start)
            start_mtg
            ;;
        stop)
            stop_mtg
            ;;
        status)
            if is_mtg_running; then
                echo -e "${GREEN}mtg is running${NC}"
                show_proxy_url
            else
                echo -e "${YELLOW}mtg is not running${NC}"
            fi
            ;;
        uninstall)
            uninstall_mtg
            ;;
        *)
            echo "Usage: $0 {install|start|stop|status|uninstall}"
            exit 1
            ;;
    esac
}

main "$@"
