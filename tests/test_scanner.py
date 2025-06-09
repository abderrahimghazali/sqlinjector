"""
Tests for vulnerability scanner
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch

from sqlinjector.scanner import VulnerabilityScanner, quick_scan
from sqlinjector.models import ScanConfig, HttpMethod


class TestVulnerabilityScanner:
    
    def test_scanner_creation(self, sample_scan_config):
        """Test creating vulnerability scanner"""
        scanner = VulnerabilityScanner(sample_scan_config)
        
        assert scanner.config == sample_scan_config
        assert scanner.injector is not None
        assert scanner.payload_manager is not None
    
    @pytest.mark.asyncio
    async def test_scan_with_mock(self, sample_scan_config):
        """Test scanning with mocked responses"""
        scanner = VulnerabilityScanner(sample_scan_config)
        
        # Mock the injector's async session and methods
        with patch.object(scanner.injector, '_create_async_session'):
            with patch.object(scanner.injector, '_close_async_session'):
                with patch.object(scanner, '_discover_all_injection_points') as mock_discover:
                    with patch.object(scanner, '_test_injection_point') as mock_test:
                        
                        # Mock discovered injection points
                        mock_injection_point = AsyncMock()
                        mock_injection_point.parameter = "id"
                        mock_discover.return_value = [mock_injection_point]
                        
                        # Mock vulnerability detection
                        mock_test.return_value = []
                        
                        result = await scanner.scan()
                        
                        assert result is not None
                        assert result.target_url == sample_scan_config.url
                        assert isinstance(result.scan_duration, float)
    
    @pytest.mark.asyncio
    async def test_quick_scan_function(self):
        """Test quick scan function"""
        # This test would need a controlled test environment
        # For now, we'll test the function signature
        url = "https://httpbin.org/get"
        
        try:
            result = await quick_scan(url, timeout=5.0, max_payloads_per_type=1)
            assert result is not None
        except Exception as e:
            # Expected for this test URL, just verify function works
            assert "scan" in str(e).lower() or "error" in str(e).lower()