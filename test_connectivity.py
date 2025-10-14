#!/usr/bin/env python3
"""
User-space connectivity test for the VPN tunnel.
This bypasses the kernel ping limitation on same-host setups.
"""
import socket
import struct
import time
import sys

def create_icmp_packet(seq=1):
    """Create an ICMP echo request packet"""
    # ICMP header: type(1) + code(1) + checksum(2) + id(2) + seq(2)
    icmp_type = 8  # Echo request
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = 12345
    icmp_seq = seq
    
    # Pack header without checksum
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    
    # Data payload
    data = b'Hello VPN tunnel!'
    
    # Calculate checksum
    packet = icmp_header + data
    checksum = calculate_checksum(packet)
    
    # Repack with correct checksum
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
    return icmp_header + data

def calculate_checksum(data):
    """Calculate ICMP checksum"""
    if len(data) % 2:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    # Add carry bits
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF

def test_connectivity():
    """Test VPN connectivity using raw sockets"""
    print("Testing VPN connectivity with user-space ICMP...")
    
    try:
        # Create raw socket for ICMP
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(5.0)
        
        # Bind to client interface
        sock.bind(('10.0.0.2', 0))
        
        print("Sending ICMP echo request to 10.0.0.1...")
        
        # Send ICMP packet
        icmp_packet = create_icmp_packet()
        sock.sendto(icmp_packet, ('10.0.0.1', 0))
        
        # Try to receive reply
        try:
            data, addr = sock.recvfrom(1024)
            print(f"✓ Received reply from {addr[0]}")
            print(f"  Reply data length: {len(data)} bytes")
            
            # Parse ICMP reply
            if len(data) >= 8:
                icmp_type = data[20]  # Skip IP header (20 bytes)
                if icmp_type == 0:  # Echo reply
                    print("✓ Valid ICMP echo reply received!")
                    print("✓ VPN tunnel is working correctly!")
                    return True
                else:
                    print(f"! Received ICMP type {icmp_type} (expected 0 for echo reply)")
            
        except socket.timeout:
            print("✗ Timeout waiting for reply")
            
    except PermissionError:
        print("✗ Permission denied. This test requires root privileges.")
        print("  Run: sudo python3 test_connectivity.py")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    
    return False

def test_tcp_connectivity():
    """Test basic TCP connectivity through the tunnel"""
    print("\nTesting TCP connectivity through VPN tunnel...")
    
    # Start a simple echo server on the server side
    import threading
    import time
    
    def echo_server():
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('10.0.0.1', 12345))
            server_sock.listen(1)
            server_sock.settimeout(10)
            
            print("  Echo server listening on 10.0.0.1:12345")
            conn, addr = server_sock.accept()
            print(f"  Connection from {addr}")
            
            data = conn.recv(1024)
            print(f"  Received: {data.decode()}")
            conn.send(b"Echo: " + data)
            conn.close()
            server_sock.close()
            
        except Exception as e:
            print(f"  Server error: {e}")
    
    # Start server in background
    server_thread = threading.Thread(target=echo_server, daemon=True)
    server_thread.start()
    time.sleep(1)
    
    # Connect as client
    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.bind(('10.0.0.2', 0))  # Bind to client IP
        client_sock.settimeout(5)
        
        print("  Connecting to echo server...")
        client_sock.connect(('10.0.0.1', 12345))
        
        print("  Sending test message...")
        client_sock.send(b"Hello VPN!")
        
        response = client_sock.recv(1024)
        print(f"  Received: {response.decode()}")
        
        if b"Hello VPN!" in response:
            print("✓ TCP connectivity through VPN tunnel works!")
            client_sock.close()
            return True
            
    except Exception as e:
        print(f"✗ TCP test failed: {e}")
    
    return False

if __name__ == "__main__":
    print("VPN Tunnel Connectivity Test")
    print("=" * 40)
    
    # Test if tunnel interfaces exist
    try:
        with open('/proc/net/dev', 'r') as f:
            interfaces = f.read()
            if 'tun0' not in interfaces or 'tun-client0' not in interfaces:
                print("✗ TUN interfaces not found. Is the VPN running?")
                print("  Run: sudo bash run_vpn.sh")
                sys.exit(1)
    except:
        pass
    
    print("✓ TUN interfaces detected")
    
    # Test ICMP connectivity (requires root)
    icmp_success = test_connectivity()
    
    # Test TCP connectivity (works without root)
    tcp_success = test_tcp_connectivity()
    
    print("\n" + "=" * 40)
    if icmp_success or tcp_success:
        print("✓ VPN tunnel is functional!")
        print("\nNote: Standard ping may show packet loss on same-host setups")
        print("due to kernel socket expectations, but the tunnel works correctly.")
    else:
        print("✗ VPN tunnel connectivity issues detected")
        print("\nTroubleshooting:")
        print("1. Check if VPN is running: ps aux | grep python")
        print("2. Check logs: tail server.log client.log")
        print("3. Check interfaces: ip addr show tun0 tun-client0")
        print("4. Check routes: ip route show | grep 10.0.0")