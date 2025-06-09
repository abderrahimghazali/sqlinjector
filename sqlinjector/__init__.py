"""
SQLInjector - SQL Injection Testing Framework

⚠️  LEGAL DISCLAIMER ⚠️
This tool is designed for authorized security testing only.
Use only on applications you own or have explicit permission to test.
Unauthorized testing is illegal and unethical.

The authors assume no responsibility for misuse of this tool.
"""

__version__ = "1.0.0"
__author__ = "AbderrahimGHAZALI"

# Legal disclaimer
LEGAL_DISCLAIMER = """
⚠️  LEGAL AND ETHICAL USE ONLY ⚠️

This tool is intended for:
- Testing your own applications
- Authorized penetration testing with written permission
- Educational purposes in controlled environments
- Bug bounty programs with proper authorization

UNAUTHORIZED USE IS ILLEGAL AND UNETHICAL.
The authors are not responsible for misuse of this tool.
"""

from .injector import SQLInjector
from .scanner import VulnerabilityScanner  
from .payloads import PayloadManager
from .exceptions import SQLInjectorError, InjectionError, ScanError

__all__ = [
    "SQLInjector",
    "VulnerabilityScanner", 
    "PayloadManager",
    "SQLInjectorError",
    "InjectionError", 
    "ScanError",
    "LEGAL_DISCLAIMER"
]

# Display disclaimer on import
import sys
if not any('pytest' in arg for arg in sys.argv):
    print(LEGAL_DISCLAIMER)