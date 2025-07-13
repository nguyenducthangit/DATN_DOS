#!/usr/bin/env python3
"""
Script test đơn giản để kiểm tra detector
"""

import time
from app.config import Config
from app.detector import DDoSDetector

def test_detector():
    """Test detector với dữ liệu mẫu"""
    print("=== Testing DDoS Detector ===")
    
    config = Config()
    detector = DDoSDetector(config)
    
    print(f"Initial status: {detector.current_status}")
    print(f"Initial alerts: {len(detector.get_alerts())}")
    
    # Test 1: Normal traffic
    print("\n--- Test 1: Normal Traffic ---")
    normal_data = {
        'source ip': '192.168.1.100',
        'destination ip': '192.168.1.1',
        'Rate': 30,
        'attack_type': 'BenignTraffic'
    }
    
    detector.add_sample(normal_data, False)
    print(f"Status after normal: {detector.current_status}")
    print(f"Alerts after normal: {len(detector.get_alerts())}")
    
    # Test 2: Attack traffic
    print("\n--- Test 2: Attack Traffic ---")
    attack_data = {
        'source ip': '192.168.1.200',
        'destination ip': '192.168.1.1',
        'Rate': 500,
        'attack_type': 'DDoS-SYN_Flood'
    }
    
    detector.add_sample(attack_data, True)
    print(f"Status after attack: {detector.current_status}")
    alerts = detector.get_alerts()
    print(f"Alerts after attack: {len(alerts)}")
    
    if alerts:
        print("Last alert:")
        print(f"  Time: {alerts[-1]['time']}")
        print(f"  Message: {alerts[-1]['message']}")
        print(f"  Severity: {alerts[-1]['severity']}")
        print(f"  Attack Type: {alerts[-1]['attack_type']}")
    
    # Test 3: Another attack
    print("\n--- Test 3: Another Attack ---")
    attack_data2 = {
        'source ip': '192.168.1.201',
        'destination ip': '192.168.1.1',
        'Rate': 800,
        'attack_type': 'DDoS-UDP_Flood'
    }
    
    detector.add_sample(attack_data2, True)
    print(f"Status after second attack: {detector.current_status}")
    alerts = detector.get_alerts()
    print(f"Total alerts: {len(alerts)}")
    
    # Test 4: Check stats
    print("\n--- Test 4: Attack Statistics ---")
    stats = detector.get_attack_stats()
    print(f"Total attacks: {stats['total_attacks']}")
    print(f"Blocked IPs: {stats['blocked_ips']}")
    print(f"Last attack: {stats['last_attack']}")
    print(f"Blocked IP list: {stats['blocked_ips_list']}")
    
    # Test 5: Check severity classification
    print("\n--- Test 5: Severity Classification ---")
    attack_types = [
        'DDoS-SYN_Flood',
        'DDoS-UDP_Flood',
        'Recon-PingSweep',
        'XSS',
        'Unknown'
    ]
    
    for attack_type in attack_types:
        severity = detector._get_attack_severity(attack_type)
        print(f"{attack_type}: Severity {severity}")
    
    print("\n=== Test Completed ===")

if __name__ == "__main__":
    test_detector() 