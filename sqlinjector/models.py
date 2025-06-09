"""
Data models for SQLInjector
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field, validator


class InjectionType(str, Enum):
    """Types of SQL injection"""
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BLIND = "time_blind"
    UNION_BASED = "union_based"
    ERROR_BASED = "error_based"
    STACKED_QUERIES = "stacked_queries"
    SECOND_ORDER = "second_order"


class DatabaseType(str, Enum):
    """Supported database types"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


class VulnerabilityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HttpMethod(str, Enum):
    """HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class InjectionPoint(BaseModel):
    """Represents a potential injection point"""
    parameter: str
    value: str
    location: str  # query, form, header, cookie, json
    method: HttpMethod
    original_request: Optional[Dict[str, Any]] = None


class PayloadResult(BaseModel):
    """Result of a payload execution"""
    payload: str
    response_time: float
    status_code: int
    response_length: int
    response_body: str = Field(max_length=10000)  # Limit response storage
    error_detected: bool = False
    error_message: Optional[str] = None
    injection_detected: bool = False
    injection_type: Optional[InjectionType] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class Vulnerability(BaseModel):
    """Represents a discovered vulnerability"""
    url: str
    parameter: str
    injection_point: InjectionPoint
    injection_type: InjectionType
    payload: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: VulnerabilityLevel
    database_type: Optional[DatabaseType] = None
    description: str
    evidence: List[PayloadResult] = Field(default_factory=list)
    remediation: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)


class ScanConfig(BaseModel):
    """Configuration for vulnerability scanning"""
    
    # Target configuration
    url: str
    method: HttpMethod = HttpMethod.GET
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    data: Optional[Dict[str, Any]] = None
    
    # Scan settings
    delay: float = 0.0  # Delay between requests
    timeout: float = 10.0
    max_retries: int = 3
    follow_redirects: bool = True
    verify_ssl: bool = True
    
    # Injection testing
    test_parameters: List[str] = Field(default_factory=list)  # Empty = test all
    injection_types: List[InjectionType] = Field(default_factory=lambda: list(InjectionType))
    max_payloads_per_type: int = 10
    
    # Detection settings
    error_detection: bool = True
    time_delay_threshold: float = 5.0  # Seconds
    boolean_detection: bool = True
    confidence_threshold: float = 0.7  # Minimum confidence for vulnerability detection
    
    # Output settings
    output_file: Optional[str] = None
    output_format: str = "json"  # json, xml, html
    save_responses: bool = False
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v
    
    @validator('confidence_threshold')
    def validate_confidence(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('Confidence threshold must be between 0.0 and 1.0')
        return v


class ScanResult(BaseModel):
    """Results of a vulnerability scan"""
    target_url: str
    scan_config: ScanConfig
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    scan_duration: float = 0.0
    total_requests: int = 0
    parameters_tested: List[str] = Field(default_factory=list)
    database_detected: Optional[DatabaseType] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    
    def get_vulnerabilities_by_severity(self, severity: VulnerabilityLevel) -> List[Vulnerability]:
        """Get vulnerabilities by severity level"""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_critical_vulnerabilities(self) -> List[Vulnerability]:
        """Get critical vulnerabilities"""
        return self.get_vulnerabilities_by_severity(VulnerabilityLevel.CRITICAL)
    
    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found"""
        return len(self.vulnerabilities) > 0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary statistics"""
        severity_counts = {}
        for severity in VulnerabilityLevel:
            severity_counts[severity.value] = len(self.get_vulnerabilities_by_severity(severity))
        
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
            "scan_duration": self.scan_duration,
            "total_requests": self.total_requests,
            "parameters_tested": len(self.parameters_tested),
            "database_detected": self.database_detected.value if self.database_detected else None
        }