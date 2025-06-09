"""
Vulnerability scanner for automated SQL injection testing
"""

import asyncio
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

from .models import (
    ScanConfig, ScanResult, Vulnerability, InjectionPoint, 
    InjectionType, DatabaseType, VulnerabilityLevel
)
from .injector import SQLInjector
from .payloads import PayloadManager
from .exceptions import ScanError


class VulnerabilityScanner:
    """
    Automated SQL injection vulnerability scanner
    
    Performs comprehensive scanning of web applications for SQL injection vulnerabilities
    """
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.injector = SQLInjector(config)
        self.payload_manager = PayloadManager()
        self.discovered_forms = []
        self.discovered_links = []
    
    async def scan(self) -> ScanResult:
        """
        Perform comprehensive SQL injection scan
        
        Returns:
            Detailed scan results
        """
        start_time = time.time()
        
        print(f"🔍 Starting SQL injection scan of: {self.config.url}")
        print("⚠️  ENSURE YOU HAVE AUTHORIZATION TO TEST THIS TARGET ⚠️")
        
        try:
            async with self.injector:
                # Initialize scan result
                scan_result = ScanResult(
                    target_url=self.config.url,
                    scan_config=self.config
                )
                
                # Step 1: Discovery phase
                print("📡 Discovering injection points...")
                injection_points = await self._discover_all_injection_points()
                
                if not injection_points:
                    print("❌ No injection points discovered")
                    return scan_result
                
                print(f"✅ Found {len(injection_points)} potential injection points")
                
                # Step 2: Test each injection point
                for i, point in enumerate(injection_points, 1):
                    print(f"🧪 Testing injection point {i}/{len(injection_points)}: {point.parameter}")
                    
                    vulnerabilities = await self._test_injection_point(point)
                    scan_result.vulnerabilities.extend(vulnerabilities)
                    scan_result.total_requests += self.injector.total_requests
                    
                    if vulnerabilities:
                        print(f"🚨 Found {len(vulnerabilities)} vulnerabilities in {point.parameter}")
                
                # Step 3: Database detection
                if scan_result.vulnerabilities:
                    print("🔬 Detecting database type...")
                    all_results = []
                    for vuln in scan_result.vulnerabilities:
                        all_results.extend(vuln.evidence)
                    
                    scan_result.database_detected = self.injector.detect_database_type(all_results)
                    if scan_result.database_detected:
                        print(f"🎯 Database detected: {scan_result.database_detected.value}")
                
                scan_result.scan_duration = time.time() - start_time
                scan_result.parameters_tested = [point.parameter for point in injection_points]
                
                # Print summary
                self._print_scan_summary(scan_result)
                
                return scan_result
                
        except Exception as e:
            raise ScanError(f"Scan failed: {e}")
    
    async def _discover_all_injection_points(self) -> List[InjectionPoint]:
        """Discover all potential injection points"""
        injection_points = []
        
        # Discover from target URL
        url_points = self.injector.discover_injection_points(
            self.config.url, 
            self.config.method, 
            self.config.data
        )
        injection_points.extend(url_points)
        
        # Discover from forms (if GET request to discover forms)
        if self.config.method == "GET":
            form_points = await self._discover_form_injection_points()
            injection_points.extend(form_points)
        
        # Filter by test_parameters if specified
        if self.config.test_parameters:
            injection_points = [
                point for point in injection_points 
                if point.parameter in self.config.test_parameters
            ]
        
        return injection_points
    
    async def _discover_form_injection_points(self) -> List[InjectionPoint]:
        """Discover injection points from HTML forms"""
        injection_points = []
        
        try:
            # Fetch the page to analyze forms
            async with self.injector._async_session.get(self.config.url) as response:
                html_content = await response.text()
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Find all forms
                forms = soup.find_all('form')
                
                for form in forms:
                    method = form.get('method', 'GET').upper()
                    action = form.get('action', '')
                    
                    # Resolve relative URLs
                    if action:
                        form_url = urljoin(self.config.url, action)
                    else:
                        form_url = self.config.url
                    
                    # Find all input fields
                    inputs = form.find_all(['input', 'select', 'textarea'])
                    
                    for input_elem in inputs:
                        input_type = input_elem.get('type', 'text').lower()
                        name = input_elem.get('name')
                        value = input_elem.get('value', '')
                        
                        # Skip certain input types
                        if input_type in ['submit', 'button', 'file', 'image']:
                            continue
                        
                        if name:
                            injection_points.append(InjectionPoint(
                                parameter=name,
                                value=value,
                                location="form",
                                method=method
                            ))
                
        except Exception as e:
            print(f"⚠️  Warning: Could not analyze forms: {e}")
        
        return injection_points
    
    async def _test_injection_point(self, injection_point: InjectionPoint) -> List[Vulnerability]:
        """Test a single injection point for vulnerabilities"""
        vulnerabilities = []
        
        for injection_type in self.config.injection_types:
            # Get payloads for this injection type
            payloads = self.payload_manager.get_payloads(
                injection_type, 
                limit=self.config.max_payloads_per_type
            )
            
            if not payloads:
                continue
            
            # Test the injection point with these payloads
            results = await self.injector.test_injection_point_async(injection_point, payloads)
            
            # Analyze results for vulnerabilities
            positive_results = [r for r in results if r.injection_detected]
            
            if positive_results:
                # Calculate confidence
                confidence = self.injector.calculate_confidence(results)
                
                # Determine severity
                severity = self.injector.determine_severity(injection_type)
                
                # Create vulnerability
                vulnerability = Vulnerability(
                    url=self.config.url,
                    parameter=injection_point.parameter,
                    injection_point=injection_point,
                    injection_type=injection_type,
                    payload=positive_results[0].payload,  # Use first successful payload
                    confidence=confidence,
                    severity=severity,
                    description=self._generate_vulnerability_description(
                        injection_type, injection_point.parameter
                    ),
                    evidence=positive_results,
                    remediation=self._generate_remediation_advice(injection_type)
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _generate_vulnerability_description(self, injection_type: InjectionType, parameter: str) -> str:
        """Generate vulnerability description"""
        descriptions = {
            InjectionType.BOOLEAN_BLIND: f"Boolean-based blind SQL injection in parameter '{parameter}'. "
                                        "Attackers can extract data by asking true/false questions.",
            
            InjectionType.TIME_BLIND: f"Time-based blind SQL injection in parameter '{parameter}'. "
                                     "Attackers can extract data by measuring response times.",
            
            InjectionType.UNION_BASED: f"UNION-based SQL injection in parameter '{parameter}'. "
                                      "Attackers can extract data directly from database tables.",
            
            InjectionType.ERROR_BASED: f"Error-based SQL injection in parameter '{parameter}'. "
                                      "Database errors reveal sensitive information about the system.",
            
            InjectionType.STACKED_QUERIES: f"Stacked queries SQL injection in parameter '{parameter}'. "
                                          "Attackers can execute multiple SQL statements."
        }
        
        return descriptions.get(injection_type, f"SQL injection vulnerability in parameter '{parameter}'.")
    
    def _generate_remediation_advice(self, injection_type: InjectionType) -> str:
        """Generate remediation advice"""
        return (
            "Use parameterized queries (prepared statements) instead of string concatenation. "
            "Validate and sanitize all user input. Implement proper error handling to avoid "
            "information disclosure. Use least privilege principle for database connections. "
            "Consider using stored procedures and input validation libraries."
        )
    
    def _print_scan_summary(self, scan_result: ScanResult):
        """Print scan summary"""
        print("\n" + "="*60)
        print("🔍 SCAN SUMMARY")
        print("="*60)
        
        summary = scan_result.get_summary()
        
        print(f"⏱️  Scan Duration: {summary['scan_duration']:.2f} seconds")
        print(f"📊 Total Requests: {summary['total_requests']}")
        print(f"🎯 Parameters Tested: {summary['parameters_tested']}")
        
        if summary['database_detected']:
            print(f"🗄️  Database Detected: {summary['database_detected']}")
        
        print(f"\n🚨 VULNERABILITIES FOUND: {summary['total_vulnerabilities']}")
        
        if summary['total_vulnerabilities'] > 0:
            severity_breakdown = summary['severity_breakdown']
            print(f"   🔴 Critical: {severity_breakdown['critical']}")
            print(f"   🟠 High: {severity_breakdown['high']}")
            print(f"   🟡 Medium: {severity_breakdown['medium']}")
            print(f"   🔵 Low: {severity_breakdown['low']}")
            print(f"   ℹ️  Info: {severity_breakdown['info']}")
            
            print("\n📋 VULNERABILITY DETAILS:")
            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                print(f"\n{i}. {vuln.injection_type.value.upper()} in '{vuln.parameter}'")
                print(f"   Severity: {vuln.severity.value.upper()}")
                print(f"   Confidence: {vuln.confidence:.1%}")
                print(f"   Payload: {vuln.payload}")
        else:
            print("✅ No SQL injection vulnerabilities detected")
        
        print("\n" + "="*60)


# Quick scanning functions
async def quick_scan(url: str, **kwargs) -> ScanResult:
    """
    Quick SQL injection scan of a URL
    
    Args:
        url: Target URL to scan
        **kwargs: Additional scan configuration options
        
    Returns:
        Scan results
    """
    config = ScanConfig(url=url, **kwargs)
    scanner = VulnerabilityScanner(config)
    return await scanner.scan()


def scan_url_sync(url: str, **kwargs) -> ScanResult:
    """
    Synchronous wrapper for quick_scan
    
    Args:
        url: Target URL to scan
        **kwargs: Additional scan configuration options
        
    Returns:
        Scan results
    """
    return asyncio.run(quick_scan(url, **kwargs))