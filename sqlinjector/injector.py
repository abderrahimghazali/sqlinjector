"""
Core SQL injection testing engine
"""

import asyncio
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlencode, parse_qs, urlparse
import requests
import aiohttp
from bs4 import BeautifulSoup

from .models import (
    InjectionPoint, PayloadResult, Vulnerability, InjectionType, 
    DatabaseType, VulnerabilityLevel, HttpMethod, ScanConfig
)
from .payloads import PayloadManager
from .exceptions import InjectionError


class SQLInjector:
    """
    Core SQL injection testing engine
    
    Performs various types of SQL injection tests on web applications
    """
    
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig(url="")
        self.payload_manager = PayloadManager()
        self.session = None
        self._async_session = None
        
        # Detection patterns
        self.error_patterns = self._load_error_patterns()
        self.database_fingerprints = self._load_database_fingerprints()
        
        # Request statistics
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
    
    def _load_error_patterns(self) -> Dict[DatabaseType, List[str]]:
        """Load database-specific error patterns"""
        return {
            DatabaseType.MYSQL: [
                r"You have an error in your SQL syntax",
                r"mysql_fetch_array\(\)",
                r"mysql_fetch_assoc\(\)",
                r"mysql_fetch_row\(\)",
                r"mysql_num_rows\(\)",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"com\.mysql\.jdbc",
                r"Unknown column.*in.*field list",
                r"Table.*doesn't exist",
                r"Duplicate column name",
                r"ERROR 1064.*42000",
            ],
            
            DatabaseType.POSTGRESQL: [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"PG::SyntaxError",
                r"psql.*ERROR",
                r"ERROR:.*column.*does not exist",
                r"ERROR:.*relation.*does not exist",
                r"ERROR:.*syntax error at or near",
                r"org\.postgresql\.util\.PSQLException",
            ],
            
            DatabaseType.MSSQL: [
                r"Driver.*SQL[\-\_\ ]*Server",
                r"OLE DB.*SQL Server",
                r"\bSQL Server.*Driver",
                r"Warning.*mssql_.*",
                r"\bSQL Server.*[0-9a-fA-F]{8}",
                r"Exception.*\WSystem\.Data\.SqlClient\.",
                r"Exception.*\WRoadhouse\.Cms\.",
                r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
                r"com\.microsoft\.sqlserver\.jdbc",
                r"Incorrect syntax near",
                r"Invalid column name",
                r"Cannot insert the value NULL into column",
            ],
            
            DatabaseType.ORACLE: [
                r"\bORA-[0-9]{4,5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*\Woci_.*",
                r"Warning.*\Wora_.*",
                r"oracle\.jdbc",
                r"OracleException",
                r"java\.sql\.SQLException.*oracle",
            ],
            
            DatabaseType.SQLITE: [
                r"SQLite/JDBCDriver",
                r"SQLite.Exception",
                r"System.Data.SQLite.SQLiteException",
                r"Warning.*sqlite_.*",
                r"Warning.*SQLite3::",
                r"\[SQLITE_ERROR\]",
                r"sqlite3.OperationalError:",
                r"no such column:",
                r"no such table:",
            ]
        }
    
    def _load_database_fingerprints(self) -> Dict[DatabaseType, List[str]]:
        """Load database fingerprinting patterns"""
        return {
            DatabaseType.MYSQL: [
                r"MySQL",
                r"maria",
                r"@@version",
                r"information_schema\.tables",
            ],
            DatabaseType.POSTGRESQL: [
                r"PostgreSQL",
                r"version\(\)",
                r"pg_version",
                r"pg_database",
            ],
            DatabaseType.MSSQL: [
                r"Microsoft SQL Server",
                r"@@version",
                r"sys\.databases",
                r"master\.dbo",
            ],
            DatabaseType.ORACLE: [
                r"Oracle",
                r"v\$version",
                r"all_tables",
                r"dual",
            ],
            DatabaseType.SQLITE: [
                r"SQLite",
                r"sqlite_version",
                r"sqlite_master",
            ]
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._create_async_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._close_async_session()
    
    async def _create_async_session(self):
        """Create async HTTP session"""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        connector = aiohttp.TCPConnector(
            verify_ssl=self.config.verify_ssl,
            limit=10,
            limit_per_host=5
        )
        
        self._async_session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=self.config.headers
        )
    
    async def _close_async_session(self):
        """Close async HTTP session"""
        if self._async_session:
            await self._async_session.close()
            self._async_session = None
    
    def _create_session(self):
        """Create synchronous HTTP session"""
        if not self.session:
            self.session = requests.Session()
            self.session.headers.update(self.config.headers)
            self.session.verify = self.config.verify_ssl
    
    def discover_injection_points(self, url: str, method: HttpMethod = HttpMethod.GET, 
                                 data: Optional[Dict[str, Any]] = None) -> List[InjectionPoint]:
        """
        Discover potential SQL injection points in a request
        
        Args:
            url: Target URL
            method: HTTP method
            data: Request data (for POST requests)
            
        Returns:
            List of potential injection points
        """
        injection_points = []
        
        # Parse URL for query parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            for param, values in query_params.items():
                for value in values:
                    injection_points.append(InjectionPoint(
                        parameter=param,
                        value=value,
                        location="query",
                        method=method
                    ))
        
        # Check form data
        if method in [HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH] and data:
            for param, value in data.items():
                injection_points.append(InjectionPoint(
                    parameter=param,
                    value=str(value),
                    location="form",
                    method=method
                ))
        
        # TODO: Add support for JSON parameters, headers, cookies
        
        return injection_points
    
    async def test_injection_point_async(self, injection_point: InjectionPoint, 
                                        payloads: List[str]) -> List[PayloadResult]:
        """
        Test an injection point with multiple payloads asynchronously
        
        Args:
            injection_point: Point to test
            payloads: List of payloads to test
            
        Returns:
            List of payload results
        """
        if not self._async_session:
            await self._create_async_session()
        
        results = []
        base_url = self.config.url
        
        for payload in payloads:
            try:
                # Apply delay if configured
                if self.config.delay > 0:
                    await asyncio.sleep(self.config.delay)
                
                # Prepare request
                if injection_point.location == "query":
                    # Inject into URL parameter
                    parsed_url = urlparse(base_url)
                    query_params = parse_qs(parsed_url.query)
                    query_params[injection_point.parameter] = [payload]
                    new_query = urlencode(query_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    
                    result = await self._make_async_request(test_url, injection_point.method, payload)
                    
                elif injection_point.location == "form":
                    # Inject into form data
                    test_data = self.config.data.copy() if self.config.data else {}
                    test_data[injection_point.parameter] = payload
                    
                    result = await self._make_async_request(base_url, injection_point.method, payload, data=test_data)
                
                results.append(result)
                
            except Exception as e:
                # Create error result
                error_result = PayloadResult(
                    payload=payload,
                    response_time=0.0,
                    status_code=0,
                    response_length=0,
                    response_body="",
                    error_detected=True,
                    error_message=str(e)
                )
                results.append(error_result)
        
        return results
    
    async def _make_async_request(self, url: str, method: HttpMethod, payload: str, 
                                 data: Optional[Dict] = None) -> PayloadResult:
        """Make an async HTTP request and analyze the response"""
        start_time = time.time()
        
        try:
            self.total_requests += 1
            
            # Prepare request parameters
            kwargs = {
                'headers': self.config.headers,
                'cookies': self.config.cookies,
                'allow_redirects': self.config.follow_redirects
            }
            
            if data:
                kwargs['data'] = data
            
            # Make request
            async with self._async_session.request(method.value, url, **kwargs) as response:
                response_time = time.time() - start_time
                response_body = await response.text()
                
                self.successful_requests += 1
                
                # Analyze response
                result = PayloadResult(
                    payload=payload,
                    response_time=response_time,
                    status_code=response.status,
                    response_length=len(response_body),
                    response_body=response_body[:10000]  # Limit stored response
                )
                
                # Detect errors and injections
                self._analyze_response(result)
                
                return result
                
        except Exception as e:
            self.failed_requests += 1
            response_time = time.time() - start_time
            
            return PayloadResult(
                payload=payload,
                response_time=response_time,
                status_code=0,
                response_length=0,
                response_body="",
                error_detected=True,
                error_message=str(e)
            )
    
    def _analyze_response(self, result: PayloadResult):
        """Analyze response for SQL injection indicators"""
        
        # Check for database errors
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, result.response_body, re.IGNORECASE):
                    result.error_detected = True
                    result.injection_detected = True
                    result.injection_type = InjectionType.ERROR_BASED
                    result.error_message = f"Database error detected: {db_type.value}"
                    return
        
        # Check for time-based injection
        if result.response_time > self.config.time_delay_threshold:
            result.injection_detected = True
            result.injection_type = InjectionType.TIME_BLIND
            return
        
        # Check for UNION-based injection indicators
        union_indicators = [
            r"union.*select",
            r"information_schema",
            r"table_name",
            r"column_name",
            r"database\(\)",
            r"version\(\)",
            r"user\(\)"
        ]
        
        for indicator in union_indicators:
            if re.search(indicator, result.response_body, re.IGNORECASE):
                result.injection_detected = True
                result.injection_type = InjectionType.UNION_BASED
                return
    
    def detect_database_type(self, responses: List[PayloadResult]) -> Optional[DatabaseType]:
        """
        Detect database type from responses
        
        Args:
            responses: List of payload responses
            
        Returns:
            Detected database type or None
        """
        db_scores = {db_type: 0 for db_type in DatabaseType}
        
        for response in responses:
            for db_type, patterns in self.error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response.response_body, re.IGNORECASE):
                        db_scores[db_type] += 1
            
            for db_type, patterns in self.database_fingerprints.items():
                for pattern in patterns:
                    if re.search(pattern, response.response_body, re.IGNORECASE):
                        db_scores[db_type] += 2  # Fingerprints weighted higher
        
        # Return database with highest score
        max_score = max(db_scores.values())
        if max_score > 0:
            for db_type, score in db_scores.items():
                if score == max_score:
                    return db_type
        
        return DatabaseType.UNKNOWN
    
    def calculate_confidence(self, results: List[PayloadResult]) -> float:
        """
        Calculate confidence level for detected vulnerabilities
        
        Args:
            results: List of payload results
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not results:
            return 0.0
        
        positive_indicators = 0
        total_indicators = 0
        
        for result in results:
            total_indicators += 1
            
            if result.injection_detected:
                positive_indicators += 1
                
                # Higher confidence for error-based detection
                if result.injection_type == InjectionType.ERROR_BASED:
                    positive_indicators += 1
                
                # Higher confidence for time-based if response time is significant
                if (result.injection_type == InjectionType.TIME_BLIND and 
                    result.response_time > self.config.time_delay_threshold * 2):
                    positive_indicators += 1
        
        confidence = positive_indicators / (total_indicators * 2)  # Normalize
        return min(confidence, 1.0)
    
    def determine_severity(self, injection_type: InjectionType, 
                          database_type: Optional[DatabaseType] = None) -> VulnerabilityLevel:
        """
        Determine vulnerability severity
        
        Args:
            injection_type: Type of injection detected
            database_type: Database type if known
            
        Returns:
            Severity level
        """
        # Base severity by injection type
        severity_map = {
            InjectionType.ERROR_BASED: VulnerabilityLevel.HIGH,
            InjectionType.UNION_BASED: VulnerabilityLevel.CRITICAL,
            InjectionType.BOOLEAN_BLIND: VulnerabilityLevel.HIGH,
            InjectionType.TIME_BLIND: VulnerabilityLevel.MEDIUM,
            InjectionType.STACKED_QUERIES: VulnerabilityLevel.CRITICAL,
            InjectionType.SECOND_ORDER: VulnerabilityLevel.HIGH
        }
        
        base_severity = severity_map.get(injection_type, VulnerabilityLevel.MEDIUM)
        
        # Increase severity for certain databases
        if database_type in [DatabaseType.MSSQL, DatabaseType.ORACLE]:
            if base_severity == VulnerabilityLevel.HIGH:
                return VulnerabilityLevel.CRITICAL
        
        return base_severity