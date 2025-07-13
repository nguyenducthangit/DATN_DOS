#!/usr/bin/env python3
"""
Script để kiểm tra interface mạng có sẵn
"""

import psutil
import socket
import subprocess
import sys

def check_interfaces():
    """Kiểm tra tất cả interface mạng"""
    print("=== Network Interface Check ===")
    
    # Lấy danh sách interface
    interfaces = psutil.net_if_addrs()
    
    print(f"Found {len(interfaces)} network interfaces:")
    print("-" * 50)
    
    for interface_name, addresses in interfaces.items():
        print(f"\nInterface: {interface_name}")
        
        for addr in addresses:
            if addr.family == socket.AF_INET:
                print(f"  IPv4: {addr.address}")
                print(f"  Netmask: {addr.netmask}")
                print(f"  Broadcast: {addr.broadcast}")
            elif addr.family == socket.AF_INET6:
                print(f"  IPv6: {addr.address}")
            elif addr.family == psutil.AF_LINK:
                print(f"  MAC: {addr.address}")
    
    print("\n" + "=" * 50)
    
    # Kiểm tra interface nào có thể capture packet
    print("\n=== Interface Capability Check ===")
    
    for interface_name in interfaces.keys():
        print(f"\nTesting interface: {interface_name}")
        
        # Kiểm tra xem interface có thể capture không
        try:
            # Thử tạo socket trên interface
            result = subprocess.run([
                'ip', 'link', 'show', interface_name
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                print(f"  ✓ Interface {interface_name} is available")
                
                # Kiểm tra xem có IP không
                addrs = interfaces[interface_name]
                has_ip = any(addr.family == socket.AF_INET for addr in addrs)
                
                if has_ip:
                    print(f"  ✓ Has IPv4 address")
                else:
                    print(f"  ⚠ No IPv4 address")
                    
            else:
                print(f"  ✗ Interface {interface_name} not available")
                
        except Exception as e:
            print(f"  ✗ Error checking {interface_name}: {e}")

def suggest_interface():
    """Đề xuất interface phù hợp"""
    print("\n=== Interface Suggestion ===")
    
    interfaces = psutil.net_if_addrs()
    
    # Ưu tiên các interface phổ biến
    preferred = ['eth0', 'eth1', 'wlan0', 'wlan1', 'en0', 'en1']
    
    for pref in preferred:
        if pref in interfaces:
            addrs = interfaces[pref]
            has_ip = any(addr.family == socket.AF_INET and not addr.address.startswith("127.") 
                        for addr in addrs)
            
            if has_ip:
                print(f"✓ Recommended interface: {pref}")
                return pref
    
    # Nếu không tìm thấy interface ưu tiên, tìm interface có IP
    for name, addrs in interfaces.items():
        has_ip = any(addr.family == socket.AF_INET and not addr.address.startswith("127.") 
                    for addr in addrs)
        
        if has_ip:
            print(f"✓ Alternative interface: {name}")
            return name
    
    print("⚠ No suitable interface found. Using loopback (lo)")
    return "lo"

def check_permissions():
    """Kiểm tra quyền capture packet"""
    print("\n=== Permission Check ===")
    
    try:
        # Thử tạo raw socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.close()
        print("✓ Raw socket creation successful - you have sufficient permissions")
        return True
    except PermissionError:
        print("✗ Permission denied - you need root privileges to capture packets")
        print("  Run with: sudo python3 app/app.py")
        return False
    except Exception as e:
        print(f"✗ Error creating raw socket: {e}")
        return False

def main():
    print("Network Interface Diagnostic Tool")
    print("=" * 60)
    
    check_interfaces()
    suggested = suggest_interface()
    
    print(f"\nSuggested interface for packet capture: {suggested}")
    
    # Kiểm tra quyền
    has_permission = check_permissions()
    
    print("\n" + "=" * 60)
    print("SUMMARY:")
    print(f"- Detected {len(psutil.net_if_addrs())} network interfaces")
    print(f"- Recommended interface: {suggested}")
    print(f"- Permissions: {'✓ OK' if has_permission else '✗ Need root'}")
    
    if not has_permission:
        print("\nTo run the DDoS detector:")
        print("sudo python3 app/app.py")
    else:
        print("\nYou can run the DDoS detector with:")
        print("python3 app/app.py")

if __name__ == "__main__":
    main() 