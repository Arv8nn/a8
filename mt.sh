#!/bin/bash

# Function to install dependencies (if necessary, in this case, none for compiled)
install_dependencies() {
    echo "No dependencies need to be installed for the compiled binary."
    echo "Proceeding with the setup..."
}

# Function to generate a random secret key
generate_secret_key() {
    local secret_key=$(openssl rand -base64 32)
    echo "$secret_key"
}

# Function to create proxy configuration
create_config() {
    echo "Enter the hostname (e.g., proxy.example.com):"
    read hostname
    echo "Enter the port number (e.g., 1080):"
    read port
    secret_key=$(generate_secret_key)

    # Create proxy configuration
    echo "Creating proxy configuration..."
    mkdir -p /etc/telegram-proxy
    cat <<EOF > /etc/telegram-proxy/config.json
{
    "hostname": "$hostname",
    "port": "$port",
    "secret_key": "$secret_key"
}
EOF
    echo "Configuration file created successfully."

    # Display connection link
    echo "Proxy setup complete. Use the following connection link:"
    echo "tg://proxy?hostname=$hostname&port=$port&secret_key=$secret_key"
}

# Function to run the proxy (compiled binary should be here)
run_proxy() {
    echo "Starting Telegram Proxy..."
    # Assuming the compiled binary is named 'telegram-proxy' and exists in the current directory
    if [ -f "./telegram-proxy" ]; then
        ./telegram-proxy --config /etc/telegram-proxy/config.json
    else
        echo "Error: telegram-proxy binary not found. Please ensure the compiled binary is in the current directory."
    fi
}

# Function to uninstall the proxy
uninstall_proxy() {
    echo "Uninstalling Telegram Proxy..."
    rm -rf /etc/telegram-proxy
    echo "Proxy uninstalled successfully."
}

# Main menu function
main_menu() {
    echo "Telegram Proxy Setup"
    echo "1. Install Proxy"
    echo "2. Run Proxy"
    echo "3. Uninstall Proxy"
    echo "4. Exit"
    echo -n "Please select an option: "
    read option

    case $option in
        1)
            install_dependencies
            create_config
            ;;
        2)
            run_proxy
            ;;
        3)
            uninstall_proxy
            ;;
        4)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            ;;
    esac
}

# Run the menu loop
while true; do
    main_menu
done

