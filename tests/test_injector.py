"""
Tests for SQL injection engine
"""

import pytest
import asyncio
import re
from unittest.mock import AsyncMock, patch, MagicMock

from sqlinjector.injector import SQLInjector
from sqlinjector.models import (
    ScanConfig, InjectionPoint, InjectionType, 
    DatabaseType, HttpMethod
)


class TestSQLInjector:
    
    def test_injector_creation(self, sample_scan_config):
        """Test creating SQL injector"""
        injector = SQLInjector(sample_scan_config)
        
        assert injector.config == sample_scan_config
        assert injector.payload_manager is not None
        assert injector.total_requests == 0
    
    def test_discover_injection_points_get(self):
        """Test discovering injection points from GET request"""
        config = ScanConfig(url="https://example.com/")
        injector = SQLInjector(config)
        url = "https://example.com/search.php?q=test&category=1"
        
        points = injector.discover_injection_points(url, HttpMethod.GET)
        
        assert len(points) == 2
        point_params = [p.parameter for p in points]
        assert "q" in point_params
        assert "category" in point_params
    
    def test_discover_injection_points_post(self):
        """Test discovering injection points from POST request"""
        config = ScanConfig(url="https://example.com/")
        injector = SQLInjector(config)
        url = "https://example.com/login.php"
        data = {"username": "admin", "password": "test"}
        
        points = injector.discover_injection_points(url, HttpMethod.POST, data)
        
        assert len(points) == 2
        point_params = [p.parameter for p in points]
        assert "username" in point_params
        assert "password" in point_params
    
    def test_error_pattern_detection(self, sql_injector):
        """Test database error pattern detection"""
        mysql_error = "You have an error in your SQL syntax near '1' at line 1"
        postgres_error = "ERROR: syntax error at or near \"1\""
        
        # Test MySQL detection
        for db_type, patterns in sql_injector.error_patterns.items():
            if db_type == DatabaseType.MYSQL:
                assert any(re.search(pattern, mysql_error, re.IGNORECASE) 
                          for pattern in patterns)
            elif db_type == DatabaseType.POSTGRESQL:
                assert any(re.search(pattern, postgres_error, re.IGNORECASE) 
                          for pattern in patterns)
    
    @pytest.mark.asyncio
    async def test_async_context_manager(self, sample_scan_config):
        """Test SQL injector as async context manager"""
        async with SQLInjector(sample_scan_config) as injector:
            assert injector._async_session is not None
        
        assert injector._async_session is None
    
    def test_database_detection(self, sql_injector):
        """Test database type detection"""
        from sqlinjector.models import PayloadResult
        
        # Mock results with MySQL errors
        mysql_results = [
            PayloadResult(
                payload="test",
                response_time=0.1,
                status_code=500,
                response_length=100,
                response_body="You have an error in your SQL syntax"
            )
        ]
        
        detected_db = sql_injector.detect_database_type(mysql_results)
        assert detected_db == DatabaseType.MYSQL
    
    def test_confidence_calculation(self, sql_injector):
        """Test vulnerability confidence calculation"""
        from sqlinjector.models import PayloadResult
        
        # Mock results with various detection levels
        results = [
            PayloadResult(
                payload="test1",
                response_time=0.1,
                status_code=200,
                response_length=100,
                response_body="normal",
                injection_detected=True,
                injection_type=InjectionType.ERROR_BASED
            ),
            PayloadResult(
                payload="test2",
                response_time=0.1,
                status_code=200,
                response_length=100,
                response_body="normal",
                injection_detected=False
            )
        ]
        
        confidence = sql_injector.calculate_confidence(results)
        assert 0.0 <= confidence <= 1.0
        assert confidence > 0  # At least one positive result
    
    def test_severity_determination(self, sql_injector):
        """Test vulnerability severity determination"""
        from sqlinjector.models import VulnerabilityLevel
        
        # Error-based should be high severity
        severity = sql_injector.determine_severity(InjectionType.ERROR_BASED)
        assert severity == VulnerabilityLevel.HIGH
        
        # UNION-based should be critical
        severity = sql_injector.determine_severity(InjectionType.UNION_BASED)
        assert severity == VulnerabilityLevel.CRITICAL
        
        # Time-based should be medium
        severity = sql_injector.determine_severity(InjectionType.TIME_BLIND)
        assert severity == VulnerabilityLevel.MEDIUM