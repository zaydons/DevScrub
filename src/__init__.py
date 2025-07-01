"""
DevScrub Security Scanner
"""

__version__ = "0.0.3"
__author__ = "Sal Zaydon"
__email__ = "devscrub@zaydon.email"

# Import main scanner
from .security_scanner import SecurityScanner

__all__ = ["SecurityScanner"]
