"""
Tests for SQLInjector data models
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from sqlinjector.models import (
    ScanConfig, InjectionPoint, PayloadResult, Vulnerability,
    InjectionType, DatabaseType, VulnerabilityLevel, HttpMethod
)


class TestScanConfig:
    
    def test_valid_scan_config(self):
        """Test creating valid scan configuration"""
        config = ScanConfig(
            url="https://example.com/test.php",
            method=HttpMethod.POST,
            timeout=15.0,
            delay=0.5
        )
        
        assert config.url == "https://example.com/test.php"
        assert config.method == HttpMethod.POST
        assert config.timeout == 15.0
        assert config.delay == 0.5
        assert config.verify_ssl == True
    
    def test_invalid_url(self):
        """Test invalid URL validation"""
        with pytest.raises(ValidationError):
            ScanConfig(url="invalid-url")
    
    def test_default_values(self):
        """Test default configuration values"""
        config = ScanConfig(url="https://example.com")
        
        assert config.method == HttpMethod.GET
        assert config.timeout == 10.0
        assert config.delay == 0.0
        assert config.max_retries == 3
        assert config.verify_ssl == True


class TestInjectionPoint:
    
    def test_injection_point_creation(self):
        """Test creating injection point"""
        point = InjectionPoint(
            parameter="id",
            value="1",
            location="query",
            method=HttpMethod.GET
        )
        
        assert point.parameter == "id"
        assert point.value == "1"
        assert point.location == "query"
        assert point.method == HttpMethod.GET


class TestPayloadResult:
    
    def test_successful_payload_result(self):
        """Test creating successful payload result"""
        result = PayloadResult(
            payload="' OR 1=1--",
            response_time=0.15,
            status_code=200,
            response_length=1024,
            response_body="<html>Response</html>",
            injection_detected=True,
            injection_type=InjectionType.BOOLEAN_BLIND
        )
        
        assert result.payload == "' OR 1=1--"
        assert result.response_time == 0.15
        assert result.status_code == 200
        assert result.injection_detected == True
        assert result.injection_type == InjectionType.BOOLEAN_BLIND
    
    def test_failed_payload_result(self):
        """Test creating failed payload result"""
        result = PayloadResult(
            payload="' OR 1=1--",
            response_time=0.0,
            status_code=0,
            response_length=0,
            response_body="",
            error_detected=True,
            error_message="Connection failed"
        )
        
        assert result.error_detected == True
        assert result.error_message == "Connection failed"
        assert result.injection_detected == False


class TestVulnerability:
    
    def test_vulnerability_creation(self):
        """Test creating vulnerability"""
        injection_point = InjectionPoint(
            parameter="id",
            value="1", 
            location="query",
            method=HttpMethod.GET
        )
        
        vuln = Vulnerability(
            url="https://example.com/test.php",
            parameter="id",
            injection_point=injection_point,
            injection_type=InjectionType.BOOLEAN_BLIND,
            payload="' OR 1=1--",
            confidence=0.95,
            severity=VulnerabilityLevel.HIGH,
            description="SQL injection found"
        )
        
        assert vuln.url == "https://example.com/test.php"
        assert vuln.parameter == "id"
        assert vuln.injection_type == InjectionType.BOOLEAN_BLIND
        assert vuln.confidence == 0.95
        assert vuln.severity == VulnerabilityLevel.HIGH