# Encrypted TUN-based VPN Project

## Project Overview

This is a **minimal, educational encrypted VPN implementation** using Python that creates a secure tunnel between client and server over TCP. It leverages Linux TUN (Tunnel) interfaces to intercept network traffic, encrypts it using AES-GCM, and transports it securely to the remote endpoint.

### Key Features
- **Layer 3 VPN**: Operates at the IP layer using TUN devices
- **AES-GCM Encryption**: Strong symmetric encryption with authentication
- **User-space Implementation**: No kernel modules required
- **ICMP Echo Reply Handling**: Built-in ping response generation
- **Bidirectional Communication**: Full-duplex encrypted tunnel
- **IPv4 Focus**: Filters out IPv6 to avoid complexity in single-host testing

## Architecture Overview

```
┌─────────────────┐         ┌─────────────────┐
│     Client      │         │     Server      │
│   (tun-client0) │         │     (tun0)      │
│   10.0.0.2/24   │         │   10.0.0.1/24   │
└─────────────────┘         └─────────────────┘
         │                           │
         │      Encrypted TCP        │
         │    (Port 55555)           │
         └───────────────────────────┘
              AES-GCM Tunnel
```

## File-by-File Analysis

### Core VPN Components

#### `client.py` - VPN Client
**Purpose**: Connects to VPN server and establishes encrypted tunnel from client-side TUN interface.

**Key Functions**:
- `tun_create(name)`: Creates TUN device using Linux ioctl calls
- `main()`: Core client logic with threading
- `sock_read_loop()`: Reads encrypted data from server, decrypts, writes to TUN
- `tun_read_loop()`: Reads packets from TUN, encrypts, sends to server
- `build_icmp_echo_reply()`: Generates ICMP echo replies for ping responses

**Data Flow**:
1. Connect to server via TCP socket (127.0.0.1:55555)
2. Create `tun-client0` interface with IP 10.0.0.2/24
3. Start two threads for bidirectional packet processing
4. Handle encrypted packet exchange with length-prefixed framing

#### `server.py` - VPN Server
**Purpose**: Listens for client connections and handles multiple clients with encrypted tunneling.

**Key Functions**:
- `tun_create(name)`: Creates server-side TUN device
- `handle_client(conn, aead)`: Per-client connection handler
- `sock_to_tun_loop()`: Socket → TUN packet processing
- `tun_to_sock_loop()`: TUN → Socket packet processing
- `build_icmp_echo_reply()`: Server-side ICMP echo reply generation

**Data Flow**:
1. Listen on 0.0.0.0:55555 for client connections
2. For each client: create `tun0` interface with IP 10.0.0.1/24
3. Spawn worker threads for bidirectional packet processing
4. Handle encrypted tunnel termination and cleanup

### Orchestration Scripts

#### `run_vpn.sh` - VPN Launcher
**Purpose**: Complete orchestration script for single-host VPN testing.

**Key Operations**:
- Virtual environment activation and dependency checking
- Cleanup of existing TUN interfaces
- Background server startup with logging
- Background client startup with logging
- Interface creation monitoring and IP assignment
- IP forwarding enablement
- Graceful shutdown handling

**Process Flow**:
1. Validate virtual environment
2. Install cryptography if missing
3. Clean up stale TUN interfaces
4. Start server → wait → start client
5. Monitor TUN interface creation (with timeouts)
6. Configure IP addresses and bring interfaces up
7. Enable IP forwarding
8. Wait for user interrupt (Ctrl+C)

#### `test_vpn.sh` - Connectivity Tester
**Purpose**: Automated testing script to verify VPN functionality.

**Test Sequence**:
1. **Interface Detection**: Wait for both `tun0` and `tun-client0` (15s timeout)
2. **Interface Configuration**: Ensure IPs and UP state
3. **Bidirectional Ping Tests**: 
   - Client → Server (tun-client0 → 10.0.0.1)
   - Server → Client (tun0 → 10.0.0.2)
4. **Error Reporting**: Diagnostic suggestions on failure

### Supporting Files

#### `NOTE.txt` - Quick Reference
Contains essential commands and setup notes:
- Environment activation
- Manual server startup
- IP forwarding configuration
- Useful debugging commands

#### Log Files
- `server.log`: Server-side packet processing and debug output
- `client.log`: Client-side packet processing and debug output

## Technical Architecture

### Threading Model

#### Client Threading
```
Main Thread
├── sock_read_loop (daemon)
│   ├── Receive encrypted packets
│   ├── Decrypt with AES-GCM
│   ├── Generate ICMP replies (if applicable)
│   └── Write to TUN device
└── tun_read_loop (daemon)
    ├── Read packets from TUN
    ├── Encrypt with AES-GCM
    └── Send via TCP socket
```

#### Server Threading
```
Main Thread (accept loop)
└── Per-Client Handler
    ├── sock_to_tun_loop (daemon)
    │   ├── Receive encrypted packets
    │   ├── Decrypt with AES-GCM
    │   ├── Generate ICMP replies (if applicable)
    │   └── Write to TUN device
    └── tun_to_sock_loop (daemon)
        ├── Read packets from TUN
        ├── Encrypt with AES-GCM
        └── Send via TCP socket
```

### Encryption Layer

#### AES-GCM Implementation
- **Algorithm**: AES-128-GCM (Galois/Counter Mode)
- **Key**: 16-byte pre-shared key (`b"16-byte-key-1234"`)
- **Nonce**: 12-byte counter-based nonce (4 bytes zero + 8 bytes counter)
- **Frame Format**: `[2-byte length][12-byte nonce][encrypted payload]`

#### Packet Processing Pipeline
```
Outbound: TUN → Read → Encrypt → Length-prefix → TCP Send
Inbound:  TCP Recv → Length-parse → Decrypt → TUN Write
```

### Network Layer Integration

#### TUN Device Operations
- **Creation**: Linux `ioctl()` with `TUNSETIFF`
- **Configuration**: `IFF_TUN | IFF_NO_PI` (no packet info headers)
- **IP Assignment**: Via `ip addr add` commands
- **Interface Management**: Automatic UP/DOWN via `ip link set`

#### IP Packet Handling
- **IPv4 Processing**: Full support with header parsing
- **IPv6 Filtering**: Ignored to avoid feedback loops in single-host setup
- **ICMP Echo**: User-space ping reply generation
- **Routing**: Relies on Linux kernel routing tables

## Code Flow Analysis

### Startup Sequence
1. **Environment Setup** (`run_vpn.sh`)
   - Activate Python virtual environment
   - Install dependencies
   - Clean existing interfaces

2. **Server Initialization** (`server.py`)
   - Create AES-GCM cipher object
   - Bind TCP socket to 0.0.0.0:55555
   - Enter accept loop

3. **Client Connection** (`client.py`)
   - Create AES-GCM cipher object
   - Connect to server TCP socket
   - Create TUN device

4. **Tunnel Establishment**
   - Server creates TUN device on client connection
   - Both sides configure IP addresses
   - Start bidirectional packet processing threads

### Packet Processing Flow

#### Outbound Packet (Local → Remote)
```python
# TUN Read Thread
packet = os.read(tun_fd, 65535)          # Read from TUN
if packet[0] >> 4 == 6: continue         # Skip IPv6
nonce = generate_nonce()                 # Create unique nonce
ciphertext = aead.encrypt(nonce, packet) # AES-GCM encrypt
frame = nonce + ciphertext               # Combine nonce + ciphertext
socket.sendall(len(frame) + frame)       # Send with length prefix
```

#### Inbound Packet (Remote → Local)
```python
# Socket Read Thread
length = struct.unpack("!H", socket.recv(2))[0]  # Read length
frame = socket.recv(length)                      # Read full frame
nonce, ciphertext = frame[:12], frame[12:]       # Split nonce/data
packet = aead.decrypt(nonce, ciphertext)         # AES-GCM decrypt
if is_icmp_request(packet):                      # Check for ping
    reply = build_icmp_reply(packet)             # Generate reply
    send_encrypted_reply(reply)                  # Send back
else:
    os.write(tun_fd, packet)                     # Write to TUN
```

### ICMP Echo Reply Mechanism

#### User-Space Ping Handling
The system includes sophisticated ICMP echo reply generation to handle ping requests entirely in user space:

```python
def build_icmp_echo_reply(ipv4_packet):
    # Parse IPv4 header
    # Extract ICMP payload
    # Convert echo request (type 8) to echo reply (type 0)
    # Recalculate ICMP checksum
    # Swap source/destination IPs
    # Recalculate IPv4 header checksum
    # Return complete reply packet
```

This enables ping functionality even when running client and server on the same host, where kernel-level ping socket association would normally fail.

## Security Considerations

### Cryptographic Security
- **Encryption**: AES-128-GCM provides confidentiality and authenticity
- **Nonce Management**: Counter-based nonces prevent replay attacks
- **Key Management**: Pre-shared key (PSK) model - suitable for testing/demos

### Network Security
- **No Authentication**: Accepts any client with correct PSK
- **No Forward Secrecy**: Same key used for entire session
- **Clear Text Metadata**: Packet lengths and timing visible to observers

### Operational Security
- **Root Privileges**: Required for TUN device creation
- **Local Testing**: Designed for single-host demonstration
- **Debug Logging**: Extensive logging for troubleshooting

## Dependencies and Environment

### Python Dependencies
- **cryptography**: AES-GCM implementation and cryptographic primitives
- **Standard Library**: socket, threading, struct, os, fcntl, time

### System Requirements
- **Linux**: TUN/TAP support required
- **Root Access**: Needed for TUN device creation and IP configuration
- **iptables**: For packet forwarding configuration
- **Virtual Environment**: Python venv for dependency isolation

### Network Requirements
- **IP Forwarding**: `net.ipv4.ip_forward = 1`
- **iptables Rules**: FORWARD chain acceptance for 10.0.0.0/24
- **TUN Module**: Kernel TUN/TAP support

## Usage Patterns

### Development/Testing
```bash
# Single-host testing
sudo bash run_vpn.sh
sudo bash test_vpn.sh

# Manual testing
ping -I tun-client0 10.0.0.1
```

### Production Considerations
- Replace PSK with proper key exchange
- Add client authentication
- Implement proper logging and monitoring
- Add reconnection logic
- Consider performance optimizations

## Educational Value

This project demonstrates:
- **Linux TUN/TAP Programming**: Low-level network interface creation
- **Applied Cryptography**: Proper AES-GCM usage with nonces
- **Network Programming**: TCP socket handling and packet framing
- **Systems Programming**: Integration with Linux networking stack
- **Threading Models**: Concurrent packet processing patterns
- **Protocol Implementation**: Custom VPN protocol design

The codebase serves as an excellent learning resource for understanding VPN fundamentals, network programming, and applied cryptography in a practical context.