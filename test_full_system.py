#!/usr/bin/env python3
"""
Script test toàn bộ hệ thống DDoS detection
"""

import time
import requests
import json
import subprocess
import sys
import os

def check_system_running():
    """Kiểm tra xem hệ thống có đang chạy không"""
    try:
        response = requests.get("http://localhost:5000/api/status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ System is running. Status: {data['status']}")
            return True
        else:
            print(f"✗ System responded with status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("✗ System is not running on port 5000")
        return False
    except Exception as e:
        print(f"✗ Error checking system: {e}")
        return False

def test_api_endpoints():
    """Test các API endpoints"""
    print("\n=== Testing API Endpoints ===")
    
    base_url = "http://localhost:5000"
    
    # Test status endpoint
    try:
        response = requests.get(f"{base_url}/api/status")
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Status API: {data}")
        else:
            print(f"✗ Status API failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Status API error: {e}")
    
    # Test metrics endpoint
    try:
        response = requests.get(f"{base_url}/api/metrics")
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Metrics API: {data}")
        else:
            print(f"✗ Metrics API failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Metrics API error: {e}")
    
    # Test config endpoint
    try:
        response = requests.get(f"{base_url}/api/config")
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Config API: {data}")
        else:
            print(f"✗ Config API failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Config API error: {e}")

def test_attack_simulation():
    """Test giả lập tấn công"""
    print("\n=== Testing Attack Simulation ===")
    
    # Tạo traffic giả lập
    import socket
    import threading
    
    def send_test_packets():
        try:
            # Gửi một số UDP packet để tạo traffic
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for i in range(50):
                s.sendto(b"test" * 100, ("127.0.0.1", 80))
                time.sleep(0.01)
            s.close()
            print("✓ Sent test packets")
        except Exception as e:
            print(f"✗ Error sending test packets: {e}")
    
    # Gửi packet trong background
    thread = threading.Thread(target=send_test_packets)
    thread.daemon = True
    thread.start()
    
    # Đợi một chút để hệ thống xử lý
    time.sleep(3)
    
    # Kiểm tra lại status
    try:
        response = requests.get("http://localhost:5000/api/status")
        if response.status_code == 200:
            data = response.json()
            print(f"Status after test traffic: {data['status']}")
        else:
            print("Could not check status after test traffic")
    except Exception as e:
        print(f"Error checking status: {e}")

def check_logs():
    """Kiểm tra log files"""
    print("\n=== Checking Logs ===")
    
    log_file = "ddos_detector.log"
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                print(f"✓ Log file exists with {len(lines)} lines")
                
                # Hiển thị 5 dòng cuối
                print("Last 5 log lines:")
                for line in lines[-5:]:
                    print(f"  {line.strip()}")
        except Exception as e:
            print(f"✗ Error reading log file: {e}")
    else:
        print("✗ Log file not found")

def main():
    print("Full System Test for DDoS Detection")
    print("=" * 50)
    
    # Bước 1: Kiểm tra hệ thống có chạy không
    if not check_system_running():
        print("\nSystem is not running. Please start it first:")
        print("sudo python3 app/app.py")
        return
    
    # Bước 2: Test API endpoints
    test_api_endpoints()
    
    # Bước 3: Test attack simulation
    test_attack_simulation()
    
    # Bước 4: Kiểm tra logs
    check_logs()
    
    print("\n" + "=" * 50)
    print("Test completed!")
    print("\nNext steps:")
    print("1. Open browser: http://localhost:5000")
    print("2. Go to dashboard: http://localhost:5000/dashboard/")
    print("3. Run attack test: python3 test_attack.py")
    print("4. Check logs: tail -f ddos_detector.log")

if __name__ == "__main__":
    main() 