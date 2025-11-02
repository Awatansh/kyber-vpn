#!/usr/bin/env python3
"""
Minimal TUN-based VPN server with AES-GCM encryption.
Run with sudo for TUN device access.
"""
import socket
import struct
import threading
import os
import fcntl
import time
import logging
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
    import oqs
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    KEM_ALG = "ML-KEM-512"
    USE_KEM = True
except Exception:
    USE_KEM = False

# Setup logging for key exchange
kem_logger = logging.getLogger('kem_exchange')
kem_logger.setLevel(logging.DEBUG)
kem_handler = logging.FileHandler('kem_exchange.log')
kem_handler.setFormatter(logging.Formatter('%(asctime)s - [SERVER] - %(levelname)s - %(message)s'))
kem_logger.addHandler(kem_handler)

# Configuration
TUN_DEVICE = "/dev/net/tun"
TUN_IFACE = "tun0"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 55555
PRE_SHARED_KEY = b"16-byte-key-1234" 

# TUN setup
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

def tun_create(name="tun0"):
    try:
        fd = os.open(TUN_DEVICE, os.O_RDWR)
        ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, ifr)
        return fd
    except Exception as e:
        print(f"Failed to create TUN device {name}: {e}")
        raise

def handle_client(conn, aead):
    tun = None
    try:
        # Perform KEM handshake (server side) if available to derive AEAD key
        if USE_KEM:
            try:
                print("\033[1;36m" + "="*70 + "\033[0m")
                print("\033[1;36m[SERVER] Starting ML-KEM Key Exchange\033[0m")
                print("\033[1;36m" + "="*70 + "\033[0m")
                
                kem_logger.info(f"Starting KEM handshake with algorithm: {KEM_ALG}")
                kem_logger.info(f"Client connection from: {conn.getpeername()}")
                
                # Read client's public key (length-prefixed)
                print(f"\033[1;33m[SERVER KEM] Waiting for client public key...\033[0m", flush=True)
                hdr = conn.recv(2)
                if not hdr:
                    print("\033[1;31m[SERVER KEM] ERROR: No header from client\033[0m", flush=True)
                    conn.close()
                    return
                plen, = struct.unpack("!H", hdr)
                print(f"\033[1;32m[SERVER KEM] Received header, expecting {plen} bytes\033[0m", flush=True)
                
                pk = b''
                while len(pk) < plen:
                    chunk = conn.recv(plen - len(pk))
                    if not chunk:
                        break
                    pk += chunk
                if len(pk) != plen:
                    print(f"\033[1;31m[SERVER KEM] ERROR: Incomplete public key (got {len(pk)}/{plen} bytes)\033[0m", flush=True)
                    conn.close()
                    return
                
                print(f"\033[1;32m[SERVER KEM] ✓ Received client public key ({len(pk)} bytes)\033[0m", flush=True)
                print(f"\033[1;36m[SERVER KEM] Public key preview: {pk[:32].hex()}...\033[0m", flush=True)
                
                kem_logger.info(f"Received client public key: {len(pk)} bytes")
                kem_logger.debug(f"Public key (full): {pk.hex()}")
                
                # Encapsulate to generate shared secret
                print(f"\033[1;33m[SERVER KEM] Performing encapsulation with {KEM_ALG}...\033[0m", flush=True)
                with oqs.KeyEncapsulation(KEM_ALG) as server_kem:
                    ciphertext, shared_secret = server_kem.encap_secret(pk)
                
                print(f"\033[1;32m[SERVER KEM] ✓ Encapsulation successful\033[0m", flush=True)
                print(f"\033[1;36m[SERVER KEM] Ciphertext length: {len(ciphertext)} bytes\033[0m", flush=True)
                print(f"\033[1;36m[SERVER KEM] Ciphertext preview: {ciphertext[:32].hex()}...\033[0m", flush=True)
                print(f"\033[1;36m[SERVER KEM] Shared secret length: {len(shared_secret)} bytes\033[0m", flush=True)
                print(f"\033[1;36m[SERVER KEM] Shared secret preview: {shared_secret[:16].hex()}...\033[0m", flush=True)
                
                kem_logger.info(f"Encapsulation completed: ciphertext={len(ciphertext)} bytes, shared_secret={len(shared_secret)} bytes")
                kem_logger.debug(f"Ciphertext (full): {ciphertext.hex()}")
                kem_logger.debug(f"Shared secret (full): {shared_secret.hex()}")
                
                # Send ciphertext back to client (length-prefixed)
                print(f"\033[1;33m[SERVER KEM] Sending ciphertext to client...\033[0m", flush=True)
                conn.sendall(struct.pack("!H", len(ciphertext)) + ciphertext)
                print(f"\033[1;32m[SERVER KEM] ✓ Ciphertext sent ({len(ciphertext)} bytes)\033[0m", flush=True)
                
                # Derive AES key from shared secret
                print(f"\033[1;33m[SERVER KEM] Deriving AES-GCM key using HKDF-SHA256...\033[0m", flush=True)
                hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"kyber-vpn")
                key = hkdf.derive(shared_secret)
                aead = AESGCM(key)
                
                print(f"\033[1;32m[SERVER KEM] ✓ AES-GCM key derived (32 bytes)\033[0m", flush=True)
                print(f"\033[1;36m[SERVER KEM] Key preview: {key[:16].hex()}...\033[0m", flush=True)
                print("\033[1;32m" + "="*70 + "\033[0m")
                print("\033[1;32m[SERVER] ✓✓✓ KEM HANDSHAKE COMPLETE - SECURE CHANNEL ESTABLISHED\033[0m")
                print("\033[1;32m" + "="*70 + "\033[0m\n", flush=True)
                
                kem_logger.info(f"HKDF key derivation completed: AES-GCM key={len(key)} bytes")
                kem_logger.debug(f"Derived AES-GCM key (full): {key.hex()}")
                kem_logger.info("KEM handshake SUCCESSFUL - Secure channel established")
                
            except Exception as e:
                print(f"\033[1;31m[SERVER KEM] FATAL ERROR: {e}\033[0m", flush=True)
                kem_logger.error(f"KEM handshake FAILED: {e}")
                import traceback
                kem_logger.error(f"Traceback: {traceback.format_exc()}")
                traceback.print_exc()
                conn.close()
                return
        tun = tun_create(TUN_IFACE)
        print(f"Tunnel fd {tun} opened")
        # Bring interface up + assign IP for server side (idempotent)
        os.system(f"ip addr add 10.0.0.1/24 dev {TUN_IFACE} 2>/dev/null || true")
        os.system(f"ip link set {TUN_IFACE} up 2>/dev/null || true")

        # Nonce counter for AES-GCM
        nonce_counter = 0
        def next_nonce():
            nonlocal nonce_counter
            nonce_counter += 1
            return (0).to_bytes(4, 'big') + nonce_counter.to_bytes(8, 'big')

        def build_icmp_echo_reply(ipv4_pkt: bytes):
            # Basic IPv4 header parsing (no options)
            if len(ipv4_pkt) < 34:
                return None
            if (ipv4_pkt[0] >> 4) != 4:
                return None
            ihl = (ipv4_pkt[0] & 0x0F) * 4
            if ihl < 20 or len(ipv4_pkt) < ihl + 8:
                return None
            proto = ipv4_pkt[9]
            if proto != 1:  # ICMP
                return None
            icmp_offset = ihl
            icmp = bytearray(ipv4_pkt[icmp_offset:])
            icmp_type = icmp[0]
            if icmp_type != 8:  # echo request
                return None
            # Build reply: type 0
            icmp[0] = 0
            # Zero checksum before recompute
            icmp[2] = 0; icmp[3] = 0
            # Recompute ICMP checksum
            ssum = 0
            # pad if odd
            data = icmp
            if len(data) % 2 == 1:
                data += b'\x00'
            for i in range(0, len(data), 2):
                ssum += (data[i] << 8) + data[i+1]
            while ssum >> 16:
                ssum = (ssum & 0xFFFF) + (ssum >> 16)
            csum = (~ssum) & 0xFFFF
            icmp[2] = (csum >> 8) & 0xFF
            icmp[3] = csum & 0xFF
            # Swap src/dst IPs in header
            reply = bytearray(ipv4_pkt[:ihl] + icmp)
            src = reply[12:16]
            dst = reply[16:20]
            reply[12:16] = dst
            reply[16:20] = src
            # Recompute IPv4 header checksum
            reply[10] = 0; reply[11] = 0
            ssum = 0
            hdr = reply[:ihl]
            if len(hdr) % 2 == 1:
                hdr += b'\x00'
            for i in range(0, len(hdr), 2):
                ssum += (hdr[i] << 8) + hdr[i+1]
            while ssum >> 16:
                ssum = (ssum & 0xFFFF) + (ssum >> 16)
            ip_csum = (~ssum) & 0xFFFF
            reply[10] = (ip_csum >> 8) & 0xFF
            reply[11] = ip_csum & 0xFF
            return bytes(reply)

        def sock_to_tun_loop():
            def ipv4_info(buf):
                if len(buf) >= 20 and (buf[0] >> 4) == 4:
                    src = '.'.join(map(str, buf[12:16]))
                    dst = '.'.join(map(str, buf[16:20]))
                    return f"src={src} dst={dst}"
                return ""
            try:
                while True:
                    hdr = conn.recv(2)
                    if not hdr:
                        break
                    msg_len, = struct.unpack("!H", hdr)
                    enc = b''
                    while len(enc) < msg_len:
                        chunk = conn.recv(msg_len - len(enc))
                        if not chunk:
                            break
                        enc += chunk
                    if len(enc) != msg_len:
                        print("[server] Incomplete message received")
                        break
                    nonce, ct = enc[:12], enc[12:]
                    try:
                        plain = aead.decrypt(nonce, ct, None)
                        info = ipv4_info(plain)
                        print(f"[server] socket read: enc={len(ct)} nonce={nonce.hex()} -> plain={len(plain)} {info}", flush=True)
                        
                        # Always write to TUN - let the kernel handle routing
                        os.write(tun, plain)
                        print(f"[server] TUN write: {len(plain)} bytes", flush=True)
                        
                    except Exception as e:
                        print(f"[server] Decrypt failed: {e}", flush=True)
                        break
            except Exception as e:
                print(f"[server] Socket read error: {e}", flush=True)
            finally:
                conn.close()

        def tun_to_sock_loop():
            def ipv4_info(buf):
                if len(buf) >= 20 and (buf[0] >> 4) == 4:
                    src = '.'.join(map(str, buf[12:16]))
                    dst = '.'.join(map(str, buf[16:20]))
                    return f"src={src} dst={dst}"
                return ""
            try:
                while True:
                    pkt = os.read(tun, 65535)
                    # Ignore IPv6 to avoid feedback loop in single-host test env
                    if (pkt[0] >> 4) == 6:
                        continue
                    print(f"[server] TUN read: {len(pkt)} bytes {ipv4_info(pkt)} first8={pkt[:8].hex()}", flush=True)
                    nonce = next_nonce()
                    ct = aead.encrypt(nonce, pkt, None)
                    outbound = nonce + ct
                    try:
                        conn.sendall(struct.pack("!H", len(outbound)))
                        conn.sendall(outbound)
                        print(f"[server] socket write: {len(outbound)} bytes nonce={nonce.hex()} plain={len(pkt)}", flush=True)
                    except Exception as e:
                        print(f"[server] Socket write error: {e}", flush=True)
                        break
            except Exception as e:
                print(f"[server] TUN read error: {e}", flush=True)
            finally:
                conn.close()

        t1 = threading.Thread(target=sock_to_tun_loop, daemon=True)
        t2 = threading.Thread(target=tun_to_sock_loop, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception as e:
        print(f"Client handler error: {e}")
    finally:
        if tun is not None:
            os.close(tun)
        print("Connection closed")

def main():
    # When no per-connection AEAD is provided by handshake, server code
    # will either get a per-connection aead inside handle_client (from KEM)
    # or fall back to this pre-shared key for legacy behavior.
    aead = AESGCM(PRE_SHARED_KEY)
    # Create TUN device at startup
    # TUN device creation moved back to handle_client

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((LISTEN_HOST, LISTEN_PORT))
        s.listen(4)
        print(f"Listening on {LISTEN_HOST}:{LISTEN_PORT}")
        while True:
            conn, addr = s.accept()
            print(f"Client connected from {addr}")
            threading.Thread(target=handle_client, args=(conn, aead), daemon=True).start()
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    main()