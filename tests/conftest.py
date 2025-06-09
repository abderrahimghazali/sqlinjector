"""
Test configuration and fixtures for SQLInjector
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path

from sqlinjector.models import ScanConfig, InjectionType, HttpMethod, DatabaseType
from sqlinjector.injector import SQLInjector
from sqlinjector.scanner import VulnerabilityScanner
from sqlinjector.payloads import PayloadManager


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_scan_config():
    """Sample scan configuration for testing"""
    return ScanConfig(
        url="https://testphp.vulnweb.com/artists.php?artist=1",
        method=HttpMethod.GET,
        timeout=10.0,
        delay=0.1,  # Fast for testing
        max_payloads_per_type=5
    )


@pytest.fixture
def payload_manager():
    """PayloadManager instance for testing"""
    return PayloadManager()


@pytest.fixture
def sql_injector(sample_scan_config):
    """SQLInjector instance for testing"""
    return SQLInjector(sample_scan_config)


@pytest.fixture
def vulnerability_scanner(sample_scan_config):
    """VulnerabilityScanner instance for testing"""
    return VulnerabilityScanner(sample_scan_config)


@pytest.fixture
def mock_responses():
    """Mock HTTP responses for testing"""
    return {
        "normal": {
            "status_code": 200,
            "content": "<html><body>Normal response</body></html>",
            "headers": {"Content-Type": "text/html"}
        },
        "sql_error": {
            "status_code": 500,
            "content": "You have an error in your SQL syntax near '1' at line 1",
            "headers": {"Content-Type": "text/html"}
        },
        "time_delay": {
            "status_code": 200,
            "content": "<html><body>Delayed response</body></html>",
            "headers": {"Content-Type": "text/html"},
            "delay": 6.0
        },
        "union_response": {
            "status_code": 200,
            "content": "<html><body>MySQL 5.7.34 information_schema</body></html>",
            "headers": {"Content-Type": "text/html"}
        }
    }