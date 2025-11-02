#!/usr/bin/env python3
"""
Minimal TUN-based VPN client with AES-GCM encryption.
Run with sudo for TUN device access.
"""
import socket
import struct
import threading
import os
import fcntl
import sys
import time
import logging
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#KEM QKD
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
kem_handler = logging.FileHandler('kem_exchange.log', mode='a')
kem_handler.setFormatter(logging.Formatter('%(asctime)s - [CLIENT] - %(levelname)s - %(message)s'))
kem_logger.addHandler(kem_handler)
# Configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 55555
TUN_DEVICE = "/dev/net/tun"
TUN_IFACE = "tun-client0"
PRE_SHARED_KEY = b"16-byte-key-1234"

# TUN setup
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

def tun_create(name="tun-client0"):
    try:
        fd = os.open(TUN_DEVICE, os.O_RDWR)
        ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, ifr)
        return fd
    except Exception as e:
        print(f"Failed to create TUN device {name}: {e}")
        raise

def main():
    tun = None
    s = None
    stop = threading.Event()
    try:
        print("[client] starting", flush=True)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))
        
        # Perform KEM handshake (client side) if available to derive AEAD key
        if USE_KEM:
            try:
                print("\033[1;35m" + "="*70 + "\033[0m", flush=True)
                print("\033[1;35m[CLIENT] Starting ML-KEM Key Exchange\033[0m", flush=True)
                print("\033[1;35m" + "="*70 + "\033[0m", flush=True)
                
                kem_logger.info(f"Starting KEM handshake with algorithm: {KEM_ALG}")
                kem_logger.info(f"Connecting to server: {SERVER_HOST}:{SERVER_PORT}")
                
                print(f"\033[1;33m[CLIENT KEM] Initializing {KEM_ALG} key encapsulation...\033[0m", flush=True)
                with oqs.KeyEncapsulation(KEM_ALG) as client_kem:
                    print(f"\033[1;33m[CLIENT KEM] Generating keypair...\033[0m", flush=True)
                    pub = client_kem.generate_keypair()
                    
                    print(f"\033[1;32m[CLIENT KEM] ✓ Keypair generated\033[0m", flush=True)
                    print(f"\033[1;36m[CLIENT KEM] Public key length: {len(pub)} bytes\033[0m", flush=True)
                    print(f"\033[1;36m[CLIENT KEM] Public key preview: {pub[:32].hex()}...\033[0m", flush=True)
                    
                    kem_logger.info(f"Keypair generated: public_key={len(pub)} bytes")
                    kem_logger.debug(f"Public key (full): {pub.hex()}")
                    
                    # Send client's public key (length-prefixed)
                    print(f"\033[1;33m[CLIENT KEM] Sending public key to server...\033[0m", flush=True)
                    s.sendall(struct.pack("!H", len(pub)) + pub)
                    print(f"\033[1;32m[CLIENT KEM] ✓ Public key sent ({len(pub)} bytes)\033[0m", flush=True)
                    
                    # Receive ciphertext from server
                    print(f"\033[1;33m[CLIENT KEM] Waiting for ciphertext from server...\033[0m", flush=True)
                    hdr = s.recv(2)
                    if not hdr:
                        print("\033[1;31m[CLIENT KEM] ERROR: No header from server\033[0m", flush=True)
                        return
                    ctlen, = struct.unpack("!H", hdr)
                    print(f"\033[1;32m[CLIENT KEM] Received header, expecting {ctlen} bytes\033[0m", flush=True)
                    
                    ct = b''
                    while len(ct) < ctlen:
                        chunk = s.recv(ctlen - len(ct))
                        if not chunk:
                            break
                        ct += chunk
                    if len(ct) != ctlen:
                        print(f"\033[1;31m[CLIENT KEM] ERROR: Incomplete ciphertext (got {len(ct)}/{ctlen} bytes)\033[0m", flush=True)
                        return
                    
                    print(f"\033[1;32m[CLIENT KEM] ✓ Received ciphertext ({len(ct)} bytes)\033[0m", flush=True)
                    print(f"\033[1;36m[CLIENT KEM] Ciphertext preview: {ct[:32].hex()}...\033[0m", flush=True)
                    
                    kem_logger.info(f"Received ciphertext from server: {len(ct)} bytes")
                    kem_logger.debug(f"Ciphertext (full): {ct.hex()}")
                    
                    # Decapsulate to recover shared secret
                    print(f"\033[1;33m[CLIENT KEM] Performing decapsulation...\033[0m", flush=True)
                    shared_secret = client_kem.decap_secret(ct)
                    
                    print(f"\033[1;32m[CLIENT KEM] ✓ Decapsulation successful\033[0m", flush=True)
                    print(f"\033[1;36m[CLIENT KEM] Shared secret length: {len(shared_secret)} bytes\033[0m", flush=True)
                    print(f"\033[1;36m[CLIENT KEM] Shared secret preview: {shared_secret[:16].hex()}...\033[0m", flush=True)
                    
                    kem_logger.info(f"Decapsulation completed: shared_secret={len(shared_secret)} bytes")
                    kem_logger.debug(f"Shared secret (full): {shared_secret.hex()}")
                
                # Derive AES key from shared secret
                print(f"\033[1;33m[CLIENT KEM] Deriving AES-GCM key using HKDF-SHA256...\033[0m", flush=True)
                hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"kyber-vpn")
                key = hkdf.derive(shared_secret)
                aead = AESGCM(key)
                
                print(f"\033[1;32m[CLIENT KEM] ✓ AES-GCM key derived (32 bytes)\033[0m", flush=True)
                print(f"\033[1;36m[CLIENT KEM] Key preview: {key[:16].hex()}...\033[0m", flush=True)
                print("\033[1;32m" + "="*70 + "\033[0m", flush=True)
                print("\033[1;32m[CLIENT] ✓✓✓ KEM HANDSHAKE COMPLETE - SECURE CHANNEL ESTABLISHED\033[0m", flush=True)
                print("\033[1;32m" + "="*70 + "\033[0m\n", flush=True)
                
                kem_logger.info(f"HKDF key derivation completed: AES-GCM key={len(key)} bytes")
                kem_logger.debug(f"Derived AES-GCM key (full): {key.hex()}")
                kem_logger.info("KEM handshake SUCCESSFUL - Secure channel established")
                
            except Exception as e:
                print(f"\033[1;31m[CLIENT KEM] FATAL ERROR: {e}\033[0m", flush=True)
                kem_logger.error(f"KEM handshake FAILED: {e}")
                import traceback
                kem_logger.error(f"Traceback: {traceback.format_exc()}")
                traceback.print_exc()
                return
        else:
            aead = AESGCM(PRE_SHARED_KEY)
            print("\033[1;33m[CLIENT] Using pre-shared key (KEM not available)\033[0m", flush=True)
        
        print("[client] connected to server", flush=True)
        print("[client] connected to server", flush=True)
        tun = tun_create(TUN_IFACE)
        print("Tunnel opened", flush=True)
        # Configure interface (ignore errors if already configured)
        os.system(f"ip addr add 10.0.0.2/24 dev {TUN_IFACE} 2>/dev/null || true")
        os.system(f"ip link set {TUN_IFACE} up 2>/dev/null || true")

        nonce_counter = 0
        def next_nonce():
            nonlocal nonce_counter
            nonce_counter += 1
            return (0).to_bytes(4, 'big') + nonce_counter.to_bytes(8, 'big')

        def build_icmp_echo_reply(ipv4_pkt: bytes):
            if len(ipv4_pkt) < 34:
                return None
            if (ipv4_pkt[0] >> 4) != 4:
                return None
            ihl = (ipv4_pkt[0] & 0x0F) * 4
            if ihl < 20 or len(ipv4_pkt) < ihl + 8:
                return None
            proto = ipv4_pkt[9]
            if proto != 1:
                return None
            icmp_offset = ihl
            icmp = bytearray(ipv4_pkt[icmp_offset:])
            if icmp[0] != 8:
                return None
            icmp[0] = 0
            icmp[2] = 0; icmp[3] = 0
            ssum = 0
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
            reply = bytearray(ipv4_pkt[:ihl] + icmp)
            src = reply[12:16]
            dst = reply[16:20]
            reply[12:16] = dst
            reply[16:20] = src
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

        def sock_read_loop():
            def ipv4_info(buf):
                if len(buf) >= 20 and (buf[0] >> 4) == 4:
                    src = '.'.join(map(str, buf[12:16]))
                    dst = '.'.join(map(str, buf[16:20]))
                    return f"src={src} dst={dst}";
                return ""
            try:
                while not stop.is_set():
                    hdr = s.recv(2)
                    if not hdr:
                        print("[client] server closed connection", flush=True)
                        break
                    (msg_len,) = struct.unpack("!H", hdr)
                    enc = b''
                    while len(enc) < msg_len:
                        chunk = s.recv(msg_len - len(enc))
                        if not chunk:
                            break
                        enc += chunk
                    if len(enc) != msg_len:
                        print("[client] incomplete encrypted frame", flush=True)
                        break
                    nonce, ct = enc[:12], enc[12:]
                    try:
                        plain = aead.decrypt(nonce, ct, None)
                        info = ipv4_info(plain)
                        print(f"[client] socket read: enc={len(ct)} bytes nonce={nonce.hex()} -> plain={len(plain)} {info}", flush=True)
                        
                        # Always write to TUN - let the kernel handle routing
                        try:
                            os.write(tun, plain)
                            print(f"[client] TUN write: {len(plain)} bytes", flush=True)
                        except OSError as ioe:
                            print(f"[client] TUN write error: {ioe}", flush=True)
                            if getattr(ioe, 'errno', None) in (5, 19):
                                os.system(f"ip link set {TUN_IFACE} up 2>/dev/null || true")
                                time.sleep(0.1)
                                continue
                            break
                        
                    except Exception as e:
                        print(f"[client] decrypt failed: {e}", flush=True)
                        break
            except Exception as e:
                print(f"[client] socket read loop error: {e}", flush=True)
            finally:
                stop.set()
                print("[client] sock_read_loop exit", flush=True)

        def tun_read_loop():
            def ipv4_info(buf):
                if len(buf) >= 20 and (buf[0] >> 4) == 4:
                    src = '.'.join(map(str, buf[12:16]))
                    dst = '.'.join(map(str, buf[16:20]))
                    return f"src={src} dst={dst}"
                return ""
            try:
                while not stop.is_set():
                    try:
                        pkt = os.read(tun, 65535)
                        # Ignore IPv6 to reduce loop noise
                        if (pkt[0] >> 4) == 6:
                            continue
                        print(f"[client] TUN read: {len(pkt)} bytes {ipv4_info(pkt)} first8={pkt[:8].hex()}", flush=True)
                    except OSError as e:
                        print(f"[client] TUN read error: {e}", flush=True)
                        break
                    nonce = next_nonce()
                    try:
                        ct = aead.encrypt(nonce, pkt, None)
                    except Exception as e:
                        print(f"[client] encrypt failed: {e}", flush=True)
                        break
                    outbound = nonce + ct
                    try:
                        s.sendall(struct.pack("!H", len(outbound)) + outbound)
                        print(f"[client] socket write: {len(outbound)} bytes nonce={nonce.hex()} plain={len(pkt)}", flush=True)
                    except Exception as e:
                        print(f"[client] socket write error: {e}", flush=True)
                        break
            finally:
                stop.set()
                print("[client] tun_read_loop exit", flush=True)

        # Start threads for TUN and socket
        t1 = threading.Thread(target=sock_read_loop, daemon=True)
        t2 = threading.Thread(target=tun_read_loop, daemon=True)
        t1.start()
        t2.start()
        # Wait for either thread to finish
        while not stop.is_set():
            time.sleep(0.1)
    finally:
        stop.set()
        if s:
            try: s.close()
            except Exception: pass
        if tun:
            try: os.close(tun)
            except Exception: pass
        print("Tunnel closed", flush=True)

if __name__ == "__main__":
    main()