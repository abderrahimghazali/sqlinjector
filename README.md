# SQLInjector

A professional SQL injection testing framework for authorized security testing and penetration testing.

## ⚠️ LEGAL DISCLAIMER ⚠️

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY**

SQLInjector is designed for:
- Testing your own applications
- Authorized penetration testing with written permission
- Educational purposes in controlled environments
- Bug bounty programs with proper authorization
- Security research with responsible disclosure

**UNAUTHORIZED USE IS ILLEGAL AND UNETHICAL.** The authors are not responsible for misuse of this tool.

## ✨ Features

- 🎯 **Comprehensive Testing**: Boolean-blind, time-blind, UNION-based, error-based, and stacked query injection
- 🔍 **Intelligent Detection**: Advanced pattern matching and response analysis
- 🗄️ **Database Fingerprinting**: Automatic detection of MySQL, PostgreSQL, MSSQL, Oracle, and SQLite
- ⚡ **Async Performance**: Fast concurrent testing with configurable delays
- 🎛️ **Flexible Scanning**: Test specific parameters or discover injection points automatically
- 📊 **Detailed Reporting**: JSON, YAML, and HTML output formats with confidence scoring
- 💻 **CLI & Python API**: Use from command line or integrate into security tools
- 🛡️ **Ethical Framework**: Built-in legal disclaimers and authorization checks

## 🚀 Installation

```bash
pip install sqlinjector
```

### Development Installation

```bash
git clone https://github.com/yourusername/sqlinjector.git
cd sqlinjector
pip install -e ".[dev]"
```

## 🎯 Quick Start

### Command Line Usage

```bash
# Legal disclaimer and help
sqlinjector disclaimer

# Basic vulnerability scan
sqlinjector scan https://vulnerable-app.com/login.php

# POST request with form data
sqlinjector scan https://app.com/login.php \
  --method POST \
  --data "username=admin&password=test"

# Test specific parameters
sqlinjector scan https://app.com/search.php?q=test \
  --params q \
  --injection-types boolean_blind time_blind

# Save detailed results
sqlinjector scan https://app.com/page.php \
  --output results.json \
  --format json \
  --verbose
```

### Python API Usage

```python
import asyncio
from sqlinjector import SQLInjector, VulnerabilityScanner
from sqlinjector.models import ScanConfig, HttpMethod

# Quick scan
async def quick_test():
    from sqlinjector.scanner import quick_scan
    
    result = await quick_scan(
        "https://vulnerable-app.com/login.php",
        method="POST",
        data={"username": "admin", "password": "test"}
    )
    
    print(f"Found {len(result.vulnerabilities)} vulnerabilities")
    return result

# Detailed scanning
async def detailed_scan():
    config = ScanConfig(
        url="https://vulnerable-app.com/search.php?q=test",
        method=HttpMethod.GET,
        delay=0.5,  # Be respectful
        max_payloads_per_type=15
    )
    
    scanner = VulnerabilityScanner(config)
    result = await scanner.scan()
    
    for vuln in result.vulnerabilities:
        print(f"Found {vuln.injection_type.value} in {vuln.parameter}")
        print(f"Severity: {vuln.severity.value}")
        print(f"Confidence: {vuln.confidence:.1%}")
    
    return result

# Run scans
result = asyncio.run(quick_test())
```

## 📚 Documentation

### Injection Types Supported

1. **Boolean-based Blind**: Infers data based on true/false responses
2. **Time-based Blind**: Uses database delay functions to extract data
3. **UNION-based**: Leverages UNION statements to extract data directly
4. **Error-based**: Exploits database errors to reveal information
5. **Stacked Queries**: Executes multiple SQL statements

### Supported Databases

- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle Database
- SQLite

### CLI Commands

#### `scan` - Main vulnerability scanning
```bash
sqlinjector scan URL [OPTIONS]

Options:
  --method, -m         HTTP method (GET, POST, PUT, DELETE, PATCH)
  --data, -d          POST data (JSON or key=value pairs)
  --headers, -H       HTTP headers (key:value)
  --cookies, -c       Cookies (JSON or key=value pairs)
  --params, -p        Specific parameters to test
  --injection-types   Injection types to test
  --delay             Delay between requests (seconds)
  --timeout           Request timeout (seconds)
  --max-payloads      Maximum payloads per injection type
  --output, -o        Output file for results
  --format, -f        Output format (json, yaml, html)
  --verbose, -v       Verbose output
  --no-ssl-verify     Disable SSL verification
```

#### `test` - Test specific payload
```bash
sqlinjector test URL --payload PAYLOAD --parameter PARAM [OPTIONS]
```

#### `payloads` - List available payloads
```bash
sqlinjector payloads [--type TYPE] [--database DB] [--limit N]
```

#### `init` - Create configuration template
```bash
sqlinjector init [--output FILE] [--format FORMAT]
```

## 🔧 Configuration

### Configuration File Example

```yaml
target:
  url: https://vulnerable-app.com/login.php
  method: POST
  headers:
    User-Agent: "SQLInjector/1.0"
    Content-Type: "application/x-www-form-urlencoded"
  data:
    username: admin
    password: password

scan_settings:
  delay: 0.5
  timeout: 10.0
  max_payloads_per_type: 15
  injection_types:
    - boolean_blind
    - time_blind
    - union_based
    - error_based
  test_parameters:
    - username
    - password

detection_settings:
  time_delay_threshold: 5.0
  error_detection: true
  boolean_detection: true

output:
  save_responses: false
  output_format: json
```

### Environment Variables

```bash
export SQLINJECTOR_DELAY=0.5
export SQLINJECTOR_TIMEOUT=10
export SQLINJECTOR_USER_AGENT="Custom Scanner"
export SQLINJECTOR_VERIFY_SSL=false
```

## 🧪 Examples

### Testing a Login Form

```python
import asyncio
from sqlinjector import VulnerabilityScanner
from sqlinjector.models import ScanConfig, HttpMethod

async def test_login_form():
    config = ScanConfig(
        url="https://testphp.vulnweb.com/login.php",
        method=HttpMethod.POST,
        data={
            "uname": "admin", 
            "pass": "password"
        },
        headers={
            "User-Agent": "SQLInjector Security Test",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        delay=1.0,  # Be respectful
        max_payloads_per_type=10
    )
    
    scanner = VulnerabilityScanner(config)
    result = await scanner.scan()
    
    if result.vulnerabilities:
        print(f"🚨 Found {len(result.vulnerabilities)} vulnerabilities!")
        for vuln in result.vulnerabilities:
            print(f"  - {vuln.injection_type.value} in '{vuln.parameter}'")
    else:
        print("✅ No vulnerabilities detected")

asyncio.run(test_login_form())
```

### Custom Payload Testing

```python
from sqlinjector import SQLInjector
from sqlinjector.models import ScanConfig, InjectionPoint, HttpMethod

async def test_custom_payload():
    config = ScanConfig(
        url="https://vulnerable-app.com/search.php",
        timeout=15.0
    )
    
    # Create injection point
    injection_point = InjectionPoint(
        parameter="q",
        value="test",
        location="query",
        method=HttpMethod.GET
    )
    
    # Custom payloads
    custom_payloads = [
        "' OR 1=1--",
        "' UNION SELECT version()--",
        "'; WAITFOR DELAY '00:00:05'--"
    ]
    
    async with SQLInjector(config) as injector:
        results = await injector.test_injection_point_async(
            injection_point, 
            custom_payloads
        )
        
        for result in results:
            if result.injection_detected:
                print(f"✅ Payload worked: {result.payload}")
                print(f"   Type: {result.injection_type.value}")
                print(f"   Response time: {result.response_time:.2f}s")

asyncio.run(test_custom_payload())
```

### Batch Testing Multiple URLs

```python
import asyncio
from sqlinjector.scanner import quick_scan

async def batch_test():
    urls = [
        "https://testphp.vulnweb.com/artists.php?artist=1",
        "https://testphp.vulnweb.com/listproducts.php?cat=1",
        "https://testphp.vulnweb.com/showimage.php?file=./picture.jpg"
    ]
    
    for url in urls:
        print(f"\n🔍 Testing: {url}")
        try:
            result = await quick_scan(url, delay=1.0)
            if result.vulnerabilities:
                print(f"🚨 Found {len(result.vulnerabilities)} vulnerabilities")
            else:
                print("✅ No vulnerabilities detected")
        except Exception as e:
            print(f"❌ Error testing {url}: {e}")

asyncio.run(batch_test())
```

## 🛡️ Ethical Guidelines

### Before You Start

1. **Get Written Authorization**: Always obtain explicit written permission before testing
2. **Understand the Scope**: Know exactly what you're allowed to test
3. **Follow Responsible Disclosure**: Report findings appropriately
4. **Respect Rate Limits**: Don't overwhelm target systems
5. **Document Everything**: Keep detailed records of your testing

### Best Practices

```python
# Good: Respectful testing with delays
config = ScanConfig(
    url="https://your-app.com/test",
    delay=1.0,  # 1 second between requests
    max_payloads_per_type=5,  # Limited payloads
    timeout=10.0  # Reasonable timeout
)

# Good: Targeting specific parameters
config = ScanConfig(
    url="https://your-app.com/search",
    test_parameters=["q"],  # Only test the search parameter
    injection_types=[InjectionType.BOOLEAN_BLIND]  # Less intrusive
)
```

### Reporting Vulnerabilities

When you find vulnerabilities:

1. **Document Thoroughly**: Include payload, response, and impact
2. **Provide Remediation**: Suggest fixes and best practices
3. **Follow Disclosure Timeline**: Give developers time to fix issues
4. **Be Professional**: Communicate clearly and respectfully

## 📊 Output Formats

### JSON Output
```json
{
  "target_url": "https://example.com/login.php",
  "vulnerabilities": [
    {
      "url": "https://example.com/login.php",
      "parameter": "username",
      "injection_type": "boolean_blind",
      "payload": "' OR 1=1--",
      "confidence": 0.95,
      "severity": "high",
      "description": "Boolean-based blind SQL injection...",
      "evidence": [...],
      "remediation": "Use parameterized queries..."
    }
  ],
  "scan_duration": 45.2,
  "total_requests": 156,
  "database_detected": "mysql"
}
```

### HTML Report
SQLInjector generates professional HTML reports with:
- Executive summary
- Vulnerability details with severity ratings
- Evidence and proof-of-concept payloads
- Remediation recommendations
- Technical details for developers

## 🔬 Advanced Features

### Database Fingerprinting

```python
from sqlinjector.payloads import PayloadManager

# Get database-specific payloads
manager = PayloadManager()
mysql_payloads = manager.get_detection_payloads()["mysql"]
```

### Custom Payload Development

```python
from sqlinjector.payloads import PayloadManager
from sqlinjector.models import InjectionType

# Add custom payloads
manager = PayloadManager()
custom_payloads = [
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' AND (SELECT SUBSTRING(@@version,1,1))='5'--"
]

manager.add_custom_payloads(InjectionType.BOOLEAN_BLIND, custom_payloads)
```

### Integration with Security Tools

```python
# Integration example for security scanners
import asyncio
from sqlinjector import VulnerabilityScanner
from sqlinjector.models import ScanConfig

class SecurityScanner:
    def __init__(self):
        self.sql_scanner = None
    
    async def scan_for_sql_injection(self, target_url, **kwargs):
        config = ScanConfig(url=target_url, **kwargs)
        scanner = VulnerabilityScanner(config)
        return await scanner.scan()
    
    def format_findings(self, result):
        return {
            "tool": "SQLInjector",
            "vulnerabilities": len(result.vulnerabilities),
            "severity": "high" if result.get_critical_vulnerabilities() else "medium",
            "details": [v.dict() for v in result.vulnerabilities]
        }
```

## 🧪 Testing

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=sqlinjector --cov-report=html

# Run integration tests (requires test environment)
pytest tests/integration/ -v --slow
```

### Test Environment Setup

```bash
# Start vulnerable test application
docker-compose -f tests/docker-compose.test.yml up -d

# Run integration tests
pytest tests/integration/ -v

# Cleanup
docker-compose -f tests/docker-compose.test.yml down
```

### Development Setup

```bash
git clone https://github.com/yourusername/sqlinjector.git
cd sqlinjector
pip install -e ".[dev]"
pre-commit install
```

### Code Guidelines

- Follow PEP 8 style guidelines
- Write comprehensive tests
- Document all functions and classes
- Include type hints
- Add examples for new features

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## ⚠️ Legal Notice

This tool is provided for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations. The authors disclaim any responsibility for unauthorized or illegal use.

## 🙏 Acknowledgments

- OWASP for SQL injection testing methodologies
- PortSwigger for Burp Suite inspiration
- sqlmap project for advanced techniques
- Security research community for vulnerability patterns

---

**Remember: With great power comes great responsibility. Use SQLInjector ethically and responsibly.**