"""
Integration tests for SQLInjector

These tests require a controlled vulnerable test environment.
"""

import pytest
import asyncio
import os
from sqlinjector import VulnerabilityScanner
from sqlinjector.models import ScanConfig, HttpMethod


@pytest.mark.slow
@pytest.mark.integration
class TestIntegration:
    """Integration tests with vulnerable applications"""
    
    @pytest.fixture
    def test_app_url(self):
        """URL for test vulnerable application"""
        # This should point to a controlled test environment
        return os.getenv("SQLINJECTOR_TEST_URL", "http://localhost:8080/dvwa")
    
    @pytest.mark.asyncio
    async def test_scan_vulnerable_app(self, test_app_url):
        """Test scanning a known vulnerable application"""
        if not test_app_url.startswith("http://localhost") and not test_app_url.startswith("http://127.0.0.1"):
            pytest.skip("Integration tests only run against localhost")
        
        config = ScanConfig(
            url=f"{test_app_url}/vulnerabilities/sqli/?id=1&Submit=Submit",
            method=HttpMethod.GET,
            delay=0.1,
            timeout=10.0,
            max_payloads_per_type=3
        )
        
        scanner = VulnerabilityScanner(config)
        result = await scanner.scan()
        
        # In a real vulnerable app, we might find vulnerabilities
        assert result is not None
        assert result.scan_duration > 0
        assert result.total_requests > 0
    
    @pytest.mark.asyncio
    async def test_false_positive_detection(self):
        """Test that scanner doesn't generate false positives on safe endpoints"""
        # Test against a known safe endpoint
        config = ScanConfig(
            url="https://httpbin.org/get?test=1",
            method=HttpMethod.GET,
            delay=0.5,  # Be respectful
            timeout=10.0,
            max_payloads_per_type=2
        )
        
        scanner = VulnerabilityScanner(config)
        result = await scanner.scan()
        
        # httpbin.org should not have SQL injection vulnerabilities
        assert len(result.vulnerabilities) == 0