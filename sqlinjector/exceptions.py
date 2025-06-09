"""
Custom exceptions for SQLInjector
"""

class SQLInjectorError(Exception):
    """Base exception for SQLInjector"""
    pass

class InjectionError(SQLInjectorError):
    """Raised when injection testing fails"""
    pass

class ScanError(SQLInjectorError):
    """Raised when vulnerability scanning fails"""
    pass

class PayloadError(SQLInjectorError):
    """Raised when payload generation fails"""
    pass

class ConfigurationError(SQLInjectorError):
    """Raised when configuration is invalid"""
    pass