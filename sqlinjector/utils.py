"""
Utility functions for SQLInjector
"""

import re
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def extract_parameters_from_url(url: str) -> Dict[str, List[str]]:
    """
    Extract parameters from URL query string
    
    Args:
        url: URL to parse
        
    Returns:
        Dictionary of parameter names to value lists
    """
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def inject_parameter_in_url(url: str, parameter: str, payload: str) -> str:
    """
    Inject payload into specific URL parameter
    
    Args:
        url: Original URL
        parameter: Parameter name to inject into
        payload: Payload to inject
        
    Returns:
        Modified URL with injected payload
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    # Inject payload
    query_params[parameter] = [payload]
    
    # Rebuild URL
    new_query = urlencode(query_params, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    
    return urlunparse(new_parsed)


def extract_forms_from_html(html_content: str, base_url: str) -> List[Dict[str, Any]]:
    """
    Extract form information from HTML content
    
    Args:
        html_content: HTML content to parse
        base_url: Base URL for resolving relative form actions
        
    Returns:
        List of form dictionaries with action, method, and inputs
    """
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            # Resolve relative URLs
            if form_info['action']:
                form_info['action'] = urllib.parse.urljoin(base_url, form_info['action'])
            else:
                form_info['action'] = base_url
            
            # Extract input fields
            for input_elem in form.find_all(['input', 'select', 'textarea']):
                input_info = {
                    'name': input_elem.get('name'),
                    'type': input_elem.get('type', 'text'),
                    'value': input_elem.get('value', '')
                }
                
                if input_info['name']:
                    form_info['inputs'].append(input_info)
            
            forms.append(form_info)
        
        return forms
        
    except ImportError:
        raise ImportError("BeautifulSoup4 is required for HTML parsing")


def detect_encoding(response_headers: Dict[str, str], content: bytes) -> str:
    """
    Detect content encoding from headers or content
    
    Args:
        response_headers: HTTP response headers
        content: Response content bytes
        
    Returns:
        Detected encoding string
    """
    # Check Content-Type header
    content_type = response_headers.get('content-type', '').lower()
    
    charset_match = re.search(r'charset=([^;\s]+)', content_type)
    if charset_match:
        return charset_match.group(1)
    
    # Try to detect from content
    try:
        # Look for HTML meta charset
        content_str = content.decode('utf-8', errors='ignore')
        meta_charset = re.search(r'<meta[^>]+charset=([^"\s>]+)', content_str, re.IGNORECASE)
        if meta_charset:
            return meta_charset.group(1)
        
        # Look for XML encoding
        xml_encoding = re.search(r'<\?xml[^>]+encoding=(["\'])([^"\']+)\1', content_str, re.IGNORECASE)
        if xml_encoding:
            return xml_encoding.group(2)
            
    except UnicodeDecodeError:
        pass
    
    # Default to UTF-8
    return 'utf-8'


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text for comparison
    
    Args:
        text: Text to normalize
        
    Returns:
        Normalized text
    """
    return re.sub(r'\s+', ' ', text.strip())


def extract_error_messages(response_body: str) -> List[str]:
    """
    Extract potential error messages from response
    
    Args:
        response_body: HTTP response body
        
    Returns:
        List of extracted error messages
    """
    error_patterns = [
        r'(?i)(error|exception|warning|fatal)[::\s]([^\n\r]{1,200})',
        r'(?i)(mysql|postgresql|oracle|sql server).*?(error|exception)([^\n\r]{1,100})',
        r'(?i)stack trace:?([^\n\r]{1,300})',
        r'(?i)line \d+[:\s]([^\n\r]{1,150})',
    ]
    
    messages = []
    for pattern in error_patterns:
        matches = re.findall(pattern, response_body)
        for match in matches:
            if isinstance(match, tuple):
                message = ' '.join(match).strip()
            else:
                message = match.strip()
            
            if len(message) > 10 and message not in messages:
                messages.append(message)
    
    return messages[:10]  # Limit to first 10 messages


def calculate_response_similarity(response1: str, response2: str) -> float:
    """
    Calculate similarity between two responses
    
    Args:
        response1: First response content
        response2: Second response content
        
    Returns:
        Similarity score between 0.0 and 1.0
    """
    # Normalize responses
    norm1 = normalize_whitespace(response1.lower())
    norm2 = normalize_whitespace(response2.lower())
    
    # Simple similarity based on common substrings
    if not norm1 or not norm2:
        return 0.0
    
    # Calculate Jaccard similarity on words
    words1 = set(norm1.split())
    words2 = set(norm2.split())
    
    intersection = len(words1.intersection(words2))
    union = len(words1.union(words2))
    
    if union == 0:
        return 1.0 if len(words1) == len(words2) == 0 else 0.0
    
    return intersection / union


def generate_test_vectors(base_payload: str, variations: int = 5) -> List[str]:
    """
    Generate test vector variations of a base payload
    
    Args:
        base_payload: Base SQL injection payload
        variations: Number of variations to generate
        
    Returns:
        List of payload variations
    """
    variations_list = [base_payload]
    
    # Add comment variations
    comment_variations = [
        base_payload + " --",
        base_payload + " #", 
        base_payload + " /**/",
        base_payload + " ;--",
    ]
    variations_list.extend(comment_variations)
    
    # Add encoding variations
    encoded_variations = [
        urllib.parse.quote(base_payload),
        urllib.parse.quote_plus(base_payload),
    ]
    variations_list.extend(encoded_variations)
    
    # Add case variations
    case_variations = [
        base_payload.upper(),
        base_payload.lower(),
    ]
    variations_list.extend(case_variations)
    
    # Remove duplicates and limit
    unique_variations = list(dict.fromkeys(variations_list))
    return unique_variations[:variations + 1]  # +1 for original


def safe_decode(content: bytes, encoding: str = 'utf-8') -> str:
    """
    Safely decode bytes content to string
    
    Args:
        content: Bytes content to decode
        encoding: Encoding to use
        
    Returns:
        Decoded string
    """
    try:
        return content.decode(encoding)
    except UnicodeDecodeError:
        try:
            return content.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            return content.decode('latin-1', errors='ignore')


def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"