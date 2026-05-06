import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Optional, Any


class InputHandler:
    """Handles input sanitization and normalization for reconnaissance targets"""

    @staticmethod
    def sanitize_input(user_input: str) -> Optional[str]:
        """Remove dangerous characters and validate input"""
        if not user_input:
            return None

        # Remove whitespace and common dangerous chars
        cleaned = user_input.strip()
        cleaned = re.sub(r'[<>\"\';&|`]', '', cleaned)
        return cleaned

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain input"""
        if '://' in domain:
            domain = urlparse(domain).netloc or domain.split('://')[-1]

        # Remove www. prefix
        domain = domain.lower().replace('www.', '')

        # Remove trailing slash and port
        domain = domain.split('/')[0].split(':')[0]

        return domain

    @staticmethod
    def validate_ip_range(ip_range: str) -> Optional[str]:
        """Validate IP range format"""
        try:
            # Handle single IP
            if '/' not in ip_range:
                ipaddress.ip_address(ip_range)
                return ip_range
            # Handle CIDR notation
            network = ipaddress.ip_network(ip_range, strict=False)
            return str(network)
        except ValueError:
            return None

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Basic domain validation"""
        domain_regex = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_regex.match(domain))

    @classmethod
    def process_input(cls, raw_input: str) -> Optional[Dict[str, Any]]:
        """Main input processing function"""
        sanitized = cls.sanitize_input(raw_input)
        if not sanitized:
            return None

        # Check if it's an IP or IP range
        if re.match(r'^[\d\.\/]+$', sanitized):
            validated_ip = cls.validate_ip_range(sanitized)
            if validated_ip:
                return {'type': 'ip_range', 'target': validated_ip}

        # Treat as domain
        normalized = cls.normalize_domain(sanitized)
        if cls.validate_domain(normalized):
            return {'type': 'domain', 'target': normalized}

        return None