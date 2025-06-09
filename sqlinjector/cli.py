"""
Command Line Interface for SQLInjector
"""

import asyncio
import sys
import json
import time
from pathlib import Path
from typing import Optional, List

import click
import yaml
from tabulate import tabulate
from colorama import init as colorama_init, Fore, Style, Back

from . import __version__, LEGAL_DISCLAIMER
from .scanner import VulnerabilityScanner, quick_scan
from .injector import SQLInjector
from .models import ScanConfig, InjectionType, HttpMethod, VulnerabilityLevel
from .payloads import PayloadManager
from .exceptions import SQLInjectorError, ScanError, ConfigurationError

# Initialize colorama for Windows compatibility
colorama_init()


def print_banner():
    """Print SQLInjector banner"""
    banner = f"""
{Fore.RED}
 ██████  ██████  ██      ██ ███    ██      ██ ███████  ██████ ████████  ██████  ██████  
██      ██    ██ ██      ██ ████   ██      ██ ██      ██         ██    ██    ██ ██   ██ 
███████ ██    ██ ██      ██ ██ ██  ██      ██ █████   ██         ██    ██    ██ ██████  
     ██ ██ ▄▄ ██ ██      ██ ██  ██ ██ ██   ██ ██      ██         ██    ██    ██ ██   ██ 
███████  ██████  ███████ ██ ██   ████  █████  ███████  ██████    ██     ██████  ██   ██ 
             ▀▀                                                                          
{Style.RESET_ALL}
{Fore.CYAN}                         Professional SQL Injection Testing Framework{Style.RESET_ALL}
{Fore.YELLOW}                                        v{__version__}{Style.RESET_ALL}

{Fore.RED}⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️{Style.RESET_ALL}
"""
    print(banner)


def get_severity_color(severity: VulnerabilityLevel) -> str:
    """Get color for vulnerability severity"""
    colors = {
        VulnerabilityLevel.CRITICAL: Fore.RED + Style.BRIGHT,
        VulnerabilityLevel.HIGH: Fore.RED,
        VulnerabilityLevel.MEDIUM: Fore.YELLOW,
        VulnerabilityLevel.LOW: Fore.BLUE,
        VulnerabilityLevel.INFO: Fore.CYAN
    }
    return colors.get(severity, Fore.WHITE)


def print_legal_warning():
    """Print legal disclaimer and get user confirmation"""
    print(f"\n{Back.RED}{Fore.WHITE} LEGAL DISCLAIMER {Style.RESET_ALL}")
    print(LEGAL_DISCLAIMER)
    
    response = input(f"\n{Fore.YELLOW}Do you confirm you have authorization to test the target? (yes/no): {Style.RESET_ALL}")
    if response.lower() not in ['yes', 'y']:
        print(f"{Fore.RED}Exiting. Only test applications you own or have permission to test.{Style.RESET_ALL}")
        sys.exit(1)


@click.group()
@click.version_option(__version__)
@click.option('--no-banner', is_flag=True, help='Suppress banner display')
@click.pass_context
def main(ctx, no_banner):
    """
    SQLInjector - Professional SQL Injection Testing Framework
    
    A comprehensive tool for testing web applications for SQL injection vulnerabilities.
    
    ⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️
    """
    ctx.ensure_object(dict)
    ctx.obj['no_banner'] = no_banner
    
    if not no_banner:
        print_banner()


@main.command()
@click.argument('url')
@click.option('--method', '-m', default='GET', type=click.Choice(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']),
              help='HTTP method to use')
@click.option('--data', '-d', help='POST data (JSON string or key=value pairs)')
@click.option('--headers', '-H', multiple=True, help='HTTP headers (key:value)')
@click.option('--cookies', '-c', help='Cookies (JSON string or key=value pairs)')
@click.option('--params', '-p', multiple=True, help='Parameters to test (default: all)')
@click.option('--injection-types', '-t', multiple=True, 
              type=click.Choice([t.value for t in InjectionType]),
              help='Injection types to test (default: all)')
@click.option('--delay', default=0.0, type=float, help='Delay between requests (seconds)')
@click.option('--timeout', default=10.0, type=float, help='Request timeout (seconds)')
@click.option('--max-payloads', default=10, type=int, help='Max payloads per injection type')
@click.option('--output', '-o', help='Output file for results')
@click.option('--format', '-f', default='json', type=click.Choice(['json', 'yaml', 'html']),
              help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--no-ssl-verify', is_flag=True, help='Disable SSL certificate verification')
@click.option('--force', is_flag=True, help='Skip legal confirmation prompt')
@click.pass_context
def scan(ctx, url, method, data, headers, cookies, params, injection_types, delay, timeout, 
         max_payloads, output, format, verbose, no_ssl_verify, force):
    """
    Scan a URL for SQL injection vulnerabilities
    
    Examples:
    
    \b
    # Basic scan
    sqlinjector scan https://example.com/login.php
    
    \b
    # POST request with data
    sqlinjector scan https://example.com/login.php --method POST --data "username=admin&password=test"
    
    \b
    # Test specific parameters
    sqlinjector scan https://example.com/search.php?q=test --params q
    
    \b
    # Custom headers and cookies
    sqlinjector scan https://example.com/api/users -H "Authorization:Bearer token" --cookies "session=abc123"
    
    \b
    # Save results to file
    sqlinjector scan https://example.com/page.php --output results.json
    """
    
    if not force and not ctx.obj.get('no_banner'):
        print_legal_warning()
    
    try:
        # Parse additional parameters
        parsed_headers = {}
        for header in headers:
            if ':' in header:
                key, value = header.split(':', 1)
                parsed_headers[key.strip()] = value.strip()
        
        parsed_data = {}
        if data:
            if data.startswith('{'):
                # JSON data
                parsed_data = json.loads(data)
            else:
                # Form data
                for pair in data.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        parsed_data[key] = value
        
        parsed_cookies = {}
        if cookies:
            if cookies.startswith('{'):
                # JSON cookies
                parsed_cookies = json.loads(cookies)
            else:
                # Key=value cookies
                for pair in cookies.split(';'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        parsed_cookies[key.strip()] = value.strip()
        
        # Convert injection types
        selected_injection_types = []
        if injection_types:
            selected_injection_types = [InjectionType(t) for t in injection_types]
        else:
            selected_injection_types = list(InjectionType)
        
        # Create scan configuration
        config = ScanConfig(
            url=url,
            method=HttpMethod(method),
            headers=parsed_headers,
            cookies=parsed_cookies,
            data=parsed_data if parsed_data else None,
            test_parameters=list(params) if params else [],
            injection_types=selected_injection_types,
            delay=delay,
            timeout=timeout,
            max_payloads_per_type=max_payloads,
            verify_ssl=not no_ssl_verify,
            output_file=output,
            output_format=format
        )
        
        # Run scan
        async def run_scan():
            scanner = VulnerabilityScanner(config)
            return await scanner.scan()
        
        if verbose:
            click.echo(f"{Fore.CYAN}Starting scan with configuration:{Style.RESET_ALL}")
            click.echo(f"  Target: {url}")
            click.echo(f"  Method: {method}")
            click.echo(f"  Injection Types: {', '.join([t.value for t in selected_injection_types])}")
            click.echo(f"  Max Payloads: {max_payloads}")
            click.echo("")
        
        result = asyncio.run(run_scan())
        
        # Save results if output file specified
        if output:
            save_results(result, output, format)
            click.echo(f"\n{Fore.GREEN}Results saved to: {output}{Style.RESET_ALL}")
        
        # Print summary
        print_scan_results(result, verbose)
        
        # Exit with appropriate code
        if result.vulnerabilities:
            sys.exit(1)  # Vulnerabilities found
        else:
            sys.exit(0)  # No vulnerabilities
            
    except Exception as e:
        click.echo(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.argument('url')
@click.option('--payload', '-p', required=True, help='SQL injection payload to test')
@click.option('--method', '-m', default='GET', type=click.Choice(['GET', 'POST']),
              help='HTTP method to use')
@click.option('--parameter', '--param', required=True, help='Parameter to inject payload into')
@click.option('--data', '-d', help='POST data for POST requests')
@click.option('--headers', '-H', multiple=True, help='HTTP headers (key:value)')
@click.option('--timeout', default=10.0, type=float, help='Request timeout (seconds)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--force', is_flag=True, help='Skip legal confirmation prompt')
def test(url, payload, method, parameter, data, headers, timeout, verbose, force):
    """
    Test a specific payload against a parameter
    
    Examples:
    
    \b
    # Test boolean injection
    sqlinjector test https://example.com/page.php?id=1 --payload "' OR 1=1--" --parameter id
    
    \b
    # Test POST parameter
    sqlinjector test https://example.com/login.php --method POST --payload "' OR 1=1--" --parameter username --data "username=admin&password=test"
    """
    
    if not force:
        print_legal_warning()
    
    try:
        # Parse headers
        parsed_headers = {}
        for header in headers:
            if ':' in header:
                key, value = header.split(':', 1)
                parsed_headers[key.strip()] = value.strip()
        
        # Parse data
        parsed_data = {}
        if data:
            for pair in data.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    parsed_data[key] = value
        
        # Create configuration
        config = ScanConfig(
            url=url,
            method=HttpMethod(method),
            headers=parsed_headers,
            data=parsed_data if parsed_data else None,
            timeout=timeout
        )
        
        # Run test
        async def run_test():
            injector = SQLInjector(config)
            
            # Discover injection point
            injection_points = injector.discover_injection_points(url, HttpMethod(method), parsed_data)
            target_point = None
            
            for point in injection_points:
                if point.parameter == parameter:
                    target_point = point
                    break
            
            if not target_point:
                click.echo(f"{Fore.RED}Parameter '{parameter}' not found in request{Style.RESET_ALL}")
                return None
            
            # Test the payload
            async with injector:
                results = await injector.test_injection_point_async(target_point, [payload])
                return results[0] if results else None
        
        result = asyncio.run(run_test())
        
        if result:
            print_test_result(result, verbose)
        else:
            click.echo(f"{Fore.RED}Test failed{Style.RESET_ALL}")
            
    except Exception as e:
        click.echo(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option('--type', '-t', type=click.Choice([t.value for t in InjectionType]),
              help='Injection type to list payloads for')
@click.option('--database', '-d', type=click.Choice(['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']),
              help='Database type for specific payloads')
@click.option('--limit', '-l', default=10, type=int, help='Maximum number of payloads to show')
@click.option('--output', '-o', help='Save payloads to file')
def payloads(type, database, limit, output):
    """
    List available SQL injection payloads
    
    Examples:
    
    \b
    # List boolean injection payloads
    sqlinjector payloads --type boolean_blind
    
    \b
    # List MySQL-specific payloads
    sqlinjector payloads --database mysql
    
    \b
    # Save union payloads to file
    sqlinjector payloads --type union_based --output union_payloads.txt
    """
    
    try:
        manager = PayloadManager()
        
        if type:
            injection_type = InjectionType(type)
            payload_list = manager.get_payloads(injection_type, limit=limit)
            
            click.echo(f"\n{Fore.CYAN}{injection_type.value.upper()} Payloads:{Style.RESET_ALL}")
            
        elif database:
            # Show database-specific payloads
            detection_payloads = manager.get_detection_payloads()
            payload_list = detection_payloads.get(database, [])
            
            click.echo(f"\n{Fore.CYAN}{database.upper()}-Specific Payloads:{Style.RESET_ALL}")
            
        else:
            # Show statistics
            stats = manager.get_payload_statistics()
            
            click.echo(f"\n{Fore.CYAN}Payload Statistics:{Style.RESET_ALL}")
            
            table_data = []
            for injection_type, count in stats.items():
                if injection_type.startswith('total_'):
                    continue
                table_data.append([injection_type.replace('_', ' ').title(), count])
            
            click.echo(tabulate(table_data, headers=['Injection Type', 'Payloads'], tablefmt='grid'))
            click.echo(f"\nTotal Default Payloads: {stats['total_default']}")
            click.echo(f"Total Database-Specific: {stats['total_database_specific']}")
            click.echo(f"Total All Payloads: {stats['total_all']}")
            return
        
        # Display payloads
        if payload_list:
            for i, payload in enumerate(payload_list, 1):
                click.echo(f"{i:2d}. {payload}")
            
            click.echo(f"\n{Fore.GREEN}Showing {len(payload_list)} payloads{Style.RESET_ALL}")
            
            # Save to file if requested
            if output:
                with open(output, 'w') as f:
                    for payload in payload_list:
                        f.write(payload + '\n')
                click.echo(f"{Fore.GREEN}Payloads saved to: {output}{Style.RESET_ALL}")
        else:
            click.echo(f"{Fore.YELLOW}No payloads found{Style.RESET_ALL}")
            
    except Exception as e:
        click.echo(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)


@main.command()
@click.option('--output', '-o', default='sqlinjector_config.yaml', help='Output configuration file')
@click.option('--format', '-f', default='yaml', type=click.Choice(['yaml', 'json']),
              help='Configuration format')
def init(output, format):
    """
    Create example configuration file
    
    Examples:
    
    \b
    # Create YAML config
    sqlinjector init --output config.yaml
    
    \b
    # Create JSON config
    sqlinjector init --output config.json --format json
    """
    
    try:
        # Create example configuration
        example_config = {
            'target': {
                'url': 'https://example.com/login.php',
                'method': 'POST',
                'headers': {
                    'User-Agent': 'SQLInjector/1.0',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                'data': {
                    'username': 'admin',
                    'password': 'password'
                }
            },
            'scan_settings': {
                'delay': 0.5,
                'timeout': 10.0,
                'max_payloads_per_type': 15,
                'injection_types': ['boolean_blind', 'time_blind', 'union_based', 'error_based'],
                'test_parameters': ['username', 'password']
            },
            'detection_settings': {
                'time_delay_threshold': 5.0,
                'error_detection': True,
                'boolean_detection': True
            },
            'output': {
                'save_responses': False,
                'output_format': 'json'
            }
        }
        
        # Save configuration
        if format == 'yaml':
            with open(output, 'w') as f:
                yaml.dump(example_config, f, default_flow_style=False, indent=2)
        else:
            with open(output, 'w') as f:
                json.dump(example_config, f, indent=2)
        
        click.echo(f"{Fore.GREEN}Example configuration created: {output}{Style.RESET_ALL}")
        click.echo(f"Edit the file to configure your target and scan settings.")
        click.echo(f"Then run: sqlinjector scan-config --config {output}")
        
    except Exception as e:
        click.echo(f"{Fore.RED}Error creating configuration: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)


@main.command()
def disclaimer():
    """Show legal disclaimer and usage guidelines"""
    print_banner()
    print(LEGAL_DISCLAIMER)
    
    print(f"\n{Fore.CYAN}LEGITIMATE USE CASES:{Style.RESET_ALL}")
    print("• Testing your own web applications")
    print("• Authorized penetration testing with written permission")
    print("• Educational purposes in controlled lab environments")
    print("• Bug bounty programs with proper authorization")
    print("• Security research with responsible disclosure")
    
    print(f"\n{Fore.RED}PROHIBITED USES:{Style.RESET_ALL}")
    print("• Testing applications without permission")
    print("• Malicious attacks on third-party systems")
    print("• Any illegal or unethical activities")
    
    print(f"\n{Fore.YELLOW}BEST PRACTICES:{Style.RESET_ALL}")
    print("• Always get written authorization before testing")
    print("• Use minimal payloads necessary for testing")
    print("• Implement rate limiting to avoid DoS")
    print("• Document findings for responsible disclosure")
    print("• Follow your organization's security policies")


def print_scan_results(result, verbose=False):
    """Print formatted scan results"""
    summary = result.get_summary()
    
    if summary['total_vulnerabilities'] == 0:
        click.echo(f"\n{Fore.GREEN}✅ No SQL injection vulnerabilities detected{Style.RESET_ALL}")
        return
    
    click.echo(f"\n{Fore.RED}🚨 {summary['total_vulnerabilities']} vulnerabilities found!{Style.RESET_ALL}")
    
    # Severity breakdown
    severity_breakdown = summary['severity_breakdown']
    click.echo(f"\nSeverity Breakdown:")
    click.echo(f"  🔴 Critical: {severity_breakdown['critical']}")
    click.echo(f"  🟠 High: {severity_breakdown['high']}")
    click.echo(f"  🟡 Medium: {severity_breakdown['medium']}")
    click.echo(f"  🔵 Low: {severity_breakdown['low']}")
    
    # Detailed vulnerabilities
    if verbose:
        click.echo(f"\n{Fore.CYAN}Detailed Vulnerabilities:{Style.RESET_ALL}")
        for i, vuln in enumerate(result.vulnerabilities, 1):
            severity_color = get_severity_color(vuln.severity)
            click.echo(f"\n{i}. {severity_color}{vuln.injection_type.value.upper()}{Style.RESET_ALL} "
                      f"in parameter '{vuln.parameter}'")
            click.echo(f"   Severity: {severity_color}{vuln.severity.value.upper()}{Style.RESET_ALL}")
            click.echo(f"   Confidence: {vuln.confidence:.1%}")
            click.echo(f"   Payload: {vuln.payload}")
            if len(vuln.payload) > 100:
                click.echo(f"   Payload: {vuln.payload[:100]}...")
            else:
                click.echo(f"   Payload: {vuln.payload}")


def print_test_result(result, verbose=False):
    """Print test result"""
    if result.injection_detected:
        click.echo(f"\n{Fore.RED}🚨 SQL Injection Detected!{Style.RESET_ALL}")
        click.echo(f"Type: {result.injection_type.value if result.injection_type else 'Unknown'}")
        click.echo(f"Response Time: {result.response_time:.3f}s")
        click.echo(f"Status Code: {result.status_code}")
        
        if result.error_detected and result.error_message:
            click.echo(f"Error: {result.error_message}")
        
        if verbose and result.response_body:
            click.echo(f"\nResponse (first 500 chars):")
            click.echo(result.response_body[:500])
            if len(result.response_body) > 500:
                click.echo("...")
    else:
        click.echo(f"\n{Fore.GREEN}✅ No injection detected{Style.RESET_ALL}")
        click.echo(f"Response Time: {result.response_time:.3f}s")
        click.echo(f"Status Code: {result.status_code}")


def save_results(result, output_file, format):
    """Save scan results to file"""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    if format == 'json':
        with open(output_path, 'w') as f:
            json.dump(result.dict(), f, indent=2, default=str)
    elif format == 'yaml':
        with open(output_path, 'w') as f:
            yaml.dump(result.dict(), f, default_flow_style=False, indent=2)
    elif format == 'html':
        generate_html_report(result, output_path)


def generate_html_report(result, output_path):
    """Generate HTML report"""
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SQLInjector Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .header { background: #f44336; color: white; padding: 20px; border-radius: 5px; }
            .summary { background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }
            .vulnerability { margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
            .critical { border-left: 5px solid #f44336; }
            .high { border-left: 5px solid #ff9800; }
            .medium { border-left: 5px solid #ffeb3b; }
            .low { border-left: 5px solid #2196f3; }
            .code { background: #f0f0f0; padding: 5px; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>SQLInjector Scan Report</h1>
            <p>Target: {{ result.target_url }}</p>
            <p>Scan Date: {{ result.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Total Vulnerabilities:</strong> {{ result.vulnerabilities|length }}</p>
            <p><strong>Scan Duration:</strong> {{ "%.2f"|format(result.scan_duration) }} seconds</p>
            <p><strong>Total Requests:</strong> {{ result.total_requests }}</p>
            {% if result.database_detected %}
            <p><strong>Database Detected:</strong> {{ result.database_detected.value }}</p>
            {% endif %}
        </div>
        
        {% for vuln in result.vulnerabilities %}
        <div class="vulnerability {{ vuln.severity.value }}">
            <h3>{{ vuln.injection_type.value.title() }} in '{{ vuln.parameter }}'</h3>
            <p><strong>Severity:</strong> {{ vuln.severity.value.upper() }}</p>
            <p><strong>Confidence:</strong> {{ "%.1f"|format(vuln.confidence * 100) }}%</p>
            <p><strong>Payload:</strong> <span class="code">{{ vuln.payload }}</span></p>
            <p><strong>Description:</strong> {{ vuln.description }}</p>
            <p><strong>Remediation:</strong> {{ vuln.remediation }}</p>
        </div>
        {% endfor %}
        
        {% if not result.vulnerabilities %}
        <div class="summary">
            <h2>✅ No Vulnerabilities Found</h2>
            <p>No SQL injection vulnerabilities were detected during the scan.</p>
        </div>
        {% endif %}
    </body>
    </html>
    """
    
    from jinja2 import Template
    template = Template(html_template)
    html_content = template.render(result=result)
    
    with open(output_path, 'w') as f:
        f.write(html_content)


if __name__ == '__main__':
    main()