#!/usr/bin/env python3
"""
Script test để kiểm tra hệ thống phát hiện DDoS
"""

import time
import requests
import json
from app.config import Config
from app.detector import DDoSDetector

def test_config():
    """Test cấu hình hệ thống"""
    print("=== Testing Configuration ===")
    config = Config()
    
    print(f"Confidence threshold: {config.confidence_threshold}")
    print(f"Rate threshold: {config.rate_threshold}")
    print(f"Block rate threshold: {config.block_rate_threshold}")
    print(f"Block severity threshold: {config.block_severity_threshold}")
    print(f"Alert cooldown: {config.alert_cooldown_seconds}s")
    print(f"Max alerts: {config.max_alerts}")
    print()

def test_detector():
    """Test detector với dữ liệu mẫu"""
    print("=== Testing Detector ===")
    config = Config()
    detector = DDoSDetector(config)
    
    # Test data mẫu
    test_data = {
        'source ip': '192.168.1.100',
        'destination ip': '192.168.1.1',
        'Rate': 50,  # Rate thấp - không phải tấn công
        'attack_type': 'DDoS-SYN_Flood'
    }
    
    print("Test 1: Rate thấp (không phải tấn công)")
    detector.add_sample(test_data, False)
    print(f"Status: {detector.current_status}")
    print(f"Alerts: {len(detector.get_alerts())}")
    print()
    
    # Test data với rate cao
    test_data_high_rate = {
        'source ip': '192.168.1.101',
        'destination ip': '192.168.1.1',
        'Rate': 1500,  # Rate cao - có thể là tấn công
        'attack_type': 'DDoS-SYN_Flood'
    }
    
    print("Test 2: Rate cao (có thể là tấn công)")
    detector.add_sample(test_data_high_rate, True)
    print(f"Status: {detector.current_status}")
    alerts = detector.get_alerts()
    print(f"Alerts: {len(alerts)}")
    if alerts:
        print(f"Last alert: {alerts[-1]['message']}")
    print()
    
    # Test severity classification
    print("=== Testing Severity Classification ===")
    attack_types = [
        'DDoS-SYN_Flood',
        'DDoS-RSTFINFlood', 
        'Recon-PingSweep',
        'XSS',
        'Unknown'
    ]
    
    for attack_type in attack_types:
        severity = detector._get_attack_severity(attack_type)
        print(f"{attack_type}: Severity {severity}")
    print()

def test_api():
    """Test API endpoints"""
    print("=== Testing API Endpoints ===")
    base_url = "http://localhost:5000"
    
    try:
        # Test status endpoint
        response = requests.get(f"{base_url}/api/status")
        if response.status_code == 200:
            data = response.json()
            print(f"Status: {data['status']}")
        else:
            print(f"Status endpoint failed: {response.status_code}")
        
        # Test metrics endpoint
        response = requests.get(f"{base_url}/api/metrics")
        if response.status_code == 200:
            data = response.json()
            print(f"Metrics: {data}")
        else:
            print(f"Metrics endpoint failed: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("Server not running. Start the server first with: python app/app.py")
    print()

def main():
    """Main test function"""
    print("DDoS Detection System Test")
    print("=" * 50)
    
    test_config()
    test_detector()
    test_api()
    
    print("Test completed!")

if __name__ == "__main__":
    main() 