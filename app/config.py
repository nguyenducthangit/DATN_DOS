import os
from utils import get_default_interface

class Config:
    def __init__(self):
        # Network configuration
        self.interface = "en0"  # Default interface
        self.host = "0.0.0.0"
        self.port = 5000
        
        # Traffic analysis configuration
        self.window_size = 1.0  # Time window for traffic analysis (seconds)
        self.data_retention_minutes = 10  # How long to keep traffic data
        
        # Dashboard configuration
        self.dashboard_update_interval = 1  # Update interval (seconds)
        self.timestamp_display_duration = 300  # How long to display timestamps (seconds)
        
        # Attack detection thresholds
        self.confidence_threshold = 0.7  # Minimum confidence for attack detection
        self.rate_threshold = 100  # Minimum packet rate for attack detection
        self.block_rate_threshold = 1000  # Rate threshold for automatic IP blocking
        self.block_severity_threshold = 3  # Minimum severity for automatic blocking
        
        # Alert configuration
        self.alert_cooldown_seconds = 30  # Cooldown period for same IP attacks
        self.max_alerts = 100  # Maximum number of alerts to keep
        
        # Debug mode
        self.debug = False