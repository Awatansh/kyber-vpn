#!/bin/bash
# Script to run VPN server and client on a single machine

# Ensure virtual environment exists
VENV_PATH="./bin/activate"
if [ ! -f "$VENV_PATH" ]; then
    echo "Virtual environment not found at $VENV_PATH"
    exit 1
fi
source $VENV_PATH

# Install required dependencies
pip show cryptography > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Installing cryptography..."
    pip install cryptography
fi

# Clean up existing TUN interfaces
sudo ip link delete tun0 2>/dev/null || true
sudo ip link delete tun-client0 2>/dev/null || true



# Start server in background
echo "Starting VPN server..."
sudo -E ./bin/python3 server.py > server.log 2>&1 &
SERVER_PID=$!
sleep 2


# Start client in background
echo "Starting VPN client..."
sudo -E ./bin/python3 client.py > client.log 2>&1 &
CLIENT_PID=$!
sleep 5

# Check for KEM handshake success
echo ""
echo "Checking ML-KEM Key Exchange status..."
if grep -q "KEM HANDSHAKE COMPLETE" server.log 2>/dev/null && grep -q "KEM HANDSHAKE COMPLETE" client.log 2>/dev/null; then
    echo -e "\033[1;32m✓✓✓ ML-KEM KEY EXCHANGE SUCCESSFUL!\033[0m"
    echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    
    # Extract and display key exchange details
    echo -e "\033[1;33mServer Side:\033[0m"
    grep "PUBLIC KEY\|CIPHERTEXT\|SHARED SECRET\|AES-GCM KEY\|✓" server.log | head -10 | sed 's/\x1b\[[0-9;]*m//g' | grep -E "(Received|sent|derived|Encapsulation)" | sed 's/^/  /'
    
    echo ""
    echo -e "\033[1;35mClient Side:\033[0m"
    grep "PUBLIC KEY\|CIPHERTEXT\|SHARED SECRET\|AES-GCM KEY\|✓" client.log | head -10 | sed 's/\x1b\[[0-9;]*m//g' | grep -E "(Keypair|sent|Received|derived|Decapsulation)" | sed 's/^/  /'
    
    echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\033[1;32m✓ Secure channel established using ML-KEM-512\033[0m"
    echo -e "\033[1;32m✓ All traffic will be encrypted with derived AES-GCM key\033[0m"
    echo ""
elif grep -q "Using pre-shared key" client.log 2>/dev/null; then
    echo -e "\033[1;33m⚠ Using pre-shared key (ML-KEM not available)\033[0m"
    echo -e "\033[1;33m  Install liboqs-python for post-quantum key exchange\033[0m"
    echo ""
else
    echo -e "\033[1;31m⚠ Key exchange status unknown - check logs\033[0m"
    echo ""
fi

# Immediate debug output for tun-client0 after client start (may or may not exist yet)
echo "State of tun-client0 immediately after starting client.py:"
ip link show tun-client0 || echo "tun-client0 not present yet"

# Debug output
echo "Process list after starting server and client:"
ps aux | grep python
echo "Listing /dev/net/tun:"
ls -l /dev/net/tun

# Wait for tun0 to be created (increase attempts to 15, up to 15 seconds)
for i in {1..15}; do
    # Check if server is running
    if ! ps -p $SERVER_PID > /dev/null 2>&1; then
        echo "Server process exited unexpectedly. Check server.log for errors."
        exit 1
    fi
    if ip link show tun0 >/dev/null 2>&1; then
        echo "tun0 created"
        if ! ip addr show tun0 | grep -q '10.0.0.1/24'; then
            sudo ip addr add 10.0.0.1/24 dev tun0
        fi
        sudo ip link set tun0 up
        break
    fi
    echo "Waiting for tun0..."
    sleep 1
done
if ! ip link show tun0 >/dev/null 2>&1; then
    echo "Failed to create tun0. Check server.log for errors."
    sudo kill $SERVER_PID 2>/dev/null || true
    exit 1
fi


# Wait for tun-client0 to be created (increase attempts to 20, up to 20 seconds)
for i in {1..20}; do
    if ip link show tun-client0 >/dev/null 2>&1; then
        echo "tun-client0 created"
        echo "State of tun-client0 before IP assignment and up:"
        ip link show tun-client0
        if ! ip addr show tun-client0 | grep -q '10.0.0.2/24'; then
            sudo ip addr add 10.0.0.2/24 dev tun-client0
        fi
        sudo ip link set tun-client0 up
        echo "State of tun-client0 after IP assignment and up:"
        ip link show tun-client0
        break
    fi
    echo "Waiting for tun-client0..."
    sleep 1
done
if ! ip link show tun-client0 2>&1 | grep -q "tun-client0"; then
    echo "Failed to create tun-client0. Check client.log for errors."
    echo "Final state of tun-client0:"
    ip link show tun-client0 || echo "tun-client0 not present at final check"
    sudo kill $SERVER_PID $CLIENT_PID 2>/dev/null || true
    exit 1
fi
ps aux | grep client.py
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Add routing rules to ensure proper packet flow
sudo ip route add 10.0.0.1/32 dev tun-client0 2>/dev/null || true
sudo ip route add 10.0.0.2/32 dev tun0 2>/dev/null || true

# Ensure iptables allows forwarding for our tunnel subnet
sudo iptables -C FORWARD -s 10.0.0.0/24 -d 10.0.0.0/24 -j ACCEPT 2>/dev/null || \
sudo iptables -I FORWARD -s 10.0.0.0/24 -d 10.0.0.0/24 -j ACCEPT

# Wait for user to stop
echo "VPN running. Logs in server.log and client.log. Press Ctrl+C to stop."
trap "echo 'Stopping VPN...'; sudo kill $SERVER_PID $CLIENT_PID 2>/dev/null; sudo ip link delete tun0 2>/dev/null; sudo ip link delete tun-client0 2>/dev/null; sudo ip route del 10.0.0.1/32 dev tun-client0 2>/dev/null; sudo ip route del 10.0.0.2/32 dev tun0 2>/dev/null; wait $SERVER_PID $CLIENT_PID 2>/dev/null; deactivate; exit 0" SIGINT
wait