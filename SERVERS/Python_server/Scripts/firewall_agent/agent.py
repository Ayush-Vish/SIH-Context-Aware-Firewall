import psutil
import pydivert
import datetime
from win32api import OpenProcess
from win32process import GetModuleFileNameEx
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
import sys
import subprocess
import re
import uuid

from collections import defaultdict

class FirewallAgent:
      def __init__(self):
        # Basic protocol mapping
            self.PORT_PROTOCOL_MAP = {
                  80: "HTTP", 443: "HTTPS", 53: "DNS",
                  21: "FTP", 22: "SSH", 25: "SMTP",
                  110: "POP3", 143: "IMAP"
            }
            
            # Application rules storage
            self.app_rules = defaultdict(lambda: {
            'allowed_ips': set(),
            'allowed_domains': set(),
            'allowed_ports': set(),
            'blocked': False
            })
            
            # Traffic statistics for anomaly detection
            self.app_stats = defaultdict(lambda: {
            'bytes_sent': 0,
            'connections': 0,
            'last_activity': None
            })
            
            self.load_rules()
            
            