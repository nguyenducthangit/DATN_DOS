import os
import socket
import psutil

def get_default_interface():
    """Tự động phát hiện interface mạng phù hợp"""
    try:
        # Thử các interface phổ biến
        common_interfaces = ['eth0', 'eth1', 'wlan0', 'wlan1', 'en0', 'en1', 'lo']
        
        # Lấy danh sách interface có sẵn
        available_interfaces = psutil.net_if_addrs().keys()
        
        # Ưu tiên interface có IP và không phải loopback
        for interface in available_interfaces:
            if interface in common_interfaces:
                addrs = psutil.net_if_addrs().get(interface, [])
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        return interface
        
        # Nếu không tìm thấy, trả về interface đầu tiên có IP
        for interface in available_interfaces:
            addrs = psutil.net_if_addrs().get(interface, [])
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    return interface
        
        # Fallback về interface đầu tiên
        if available_interfaces:
            return list(available_interfaces)[0]
        
        return "lo"  # Loopback interface
    except Exception as e:
        print(f"Error detecting interface: {e}")
        return "lo"

class Config:
    def __init__(self):
        # Network configuration
        self.interface = get_default_interface()  # Tự động phát hiện interface
        self.host = "0.0.0.0"
        self.port = 5000
        
        # Traffic analysis configuration
        self.window_size = 1.0  # Time window for traffic analysis (seconds)
        self.data_retention_minutes = 10  # How long to keep traffic data
        
        # Dashboard configuration
        self.dashboard_update_interval = 1  # Update interval (seconds)
        self.timestamp_display_duration = 300  # How long to display timestamps (seconds)
        
        # Attack detection thresholds
        self.confidence_threshold = 0.5  # Giảm ngưỡng tin cậy để dễ phát hiện
        self.rate_threshold = 50  # Giảm ngưỡng rate để dễ phát hiện
        self.block_rate_threshold = 500  # Giảm ngưỡng block
        self.block_severity_threshold = 2  # Giảm ngưỡng severity để block
        
        # Alert configuration
        self.alert_cooldown_seconds = 30  # Cooldown period for same IP attacks
        self.max_alerts = 100  # Maximum number of alerts to keep
        
        # Debug mode
        self.debug = True  # Bật debug mode để dễ test
        
        print(f"Detected interface: {self.interface}")