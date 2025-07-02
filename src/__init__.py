"""
DevScrub Security Scanner
"""

__version__ = "0.0.4"
__author__ = "Sal Zaydon"
__email__ = "devscrub@zaydon.email"

# Import main scanner
from .security_scanner import SecurityScanner

__all__ = ["SecurityScanner"]
