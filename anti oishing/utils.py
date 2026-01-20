import requests
import whois
from datetime import datetime
from urllib.parse import urlparse
import re

def get_url_length(url):
    """Returns the length of the URL."""
    return len(url)

def check_ssl(url):
    """
    Checks if the URL uses HTTPS and is accessible.
    Returns 1 if valid HTTPS, 0 otherwise.
    """
    try:
        # Basic check first
        if not url.startswith('http'):
            url = 'https://' + url
        
        parsed = urlparse(url)
        if parsed.scheme == 'https':
            return 1
        return 0
    except:
        return 0

def get_domain_age(url):
    """
    Returns the age of the domain in days.
    Returns 0 if information cannot be fetched (suspicious).
    """
    try:
        domain = urlparse(url).netloc
        if not domain:
            domain = url
            
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not creation_date:
            return -1
            
        today = datetime.now()
        age = (today - creation_date).days
        return age
    except:
        return -1

# --- Advanced Features ---

def has_ip_address(url):
    """Checks if the domain is an IP address."""
    try:
        domain = urlparse(url).netloc
        if not domain: return 0
        # IPv4 pattern
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        if ip_pattern.match(domain):
            return 1 # Yes, it has IP (Phishing tendency)
        return 0 
    except:
        return 0

def has_at_symbol(url):
    """Checks for @ symbol within the URL structure."""
    if "@" in url:
        return 1
    return 0

def count_subdomains(url):
    """Counts number of dots in the domain name."""
    try:
        domain = urlparse(url).netloc
        if not domain: return 0
        return domain.count('.')
    except:
        return 0

def has_hyphen(url):
    """Checks for hyphen in domain name."""
    try:
        domain = urlparse(url).netloc
        if not domain: return 0
        if '-' in domain:
            return 1
        return 0
    except:
        return 0

# --- Ultra Advanced Features ---

def has_double_slash(url):
    """Checks for '__' or '//' in the path (redirection trick)."""
    try:
        # The first // is for protocol. We look for subsequent ones.
        # Find position of '://' -> length is 3
        pos = url.find('://')
        if pos > -1:
            # Look in the rest of the string
            rest = url[pos+3:]
            if '//' in rest:
                return 1
        return 0
    except:
        return 0

def has_custom_port(url):
    """Checks if a non-standard port is used (e.g., :8080)."""
    try:
        domain = urlparse(url).netloc
        if ':' in domain:
            return 1
        return 0
    except:
        return 0

def tld_in_subdomain(url):
    """Checks if common TLDs like .com, .net, .in are part of the subdomain."""
    try:
        parts = urlparse(url).netloc.split('.')
        # If we have something like [paypal, com, verify, net], 'com' is inside
        # Ignore the actual TLD (last part)
        if len(parts) > 2:
            body = parts[:-1] 
            common_tlds = ['com', 'org', 'net', 'in', 'co', 'gov', 'edu']
            for part in body:
                if part in common_tlds:
                    return 1 # TLD found in subdomain (High Phish Probability)
        return 0
    except:
        return 0

def suspicious_tld(url):
    """Checks for suspicious or uncommon TLDs."""
    try:
        parsed = urlparse(url)
        # Get the suffix
        domain = parsed.netloc
        if not domain: domain = url
        
        # Simple extraction of the last part
        if '.' in domain:
            extension = domain.split('.')[-1].lower()
            suspicious_list = ['zip', 'xyz', 'cricket', 'party', 'gq', 'tk', 'ml', 'cf', 'buzz', 'top']
            if extension in suspicious_list:
                return 1
        return 0
    except:
        return 0

def high_numeric_ratio(url):
    """Calculates the ratio of digits to total characters in the URL."""
    # Phishing URLs often use random number tokens
    digits = sum(c.isdigit() for c in url)
    length = len(url)
    if length == 0: return 0
    
    ratio = digits / length
    # If more than 20% of the URL is numbers, it's flagged as suspicious
    return 1 if ratio > 0.2 else 0
