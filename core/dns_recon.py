import requests
from typing import List, Dict, Any, Set


class DNSRecon:
    """DNS and subdomain reconnaissance"""

    def __init__(self, securitytrails_api_key: str):
        self.securitytrails_api_key = securitytrails_api_key

    def find_subdomains_passive(self, domain: str) -> List[str]:
        """Find subdomains using passive sources"""
        subdomains = set()

        # Certificate Transparency Logs
        ct_subdomains = self._get_crt_sh_subdomains(domain)
        subdomains.update(ct_subdomains)

        # Clean up results
        cleaned_subdomains = set()
        for sub in subdomains:
            sub = sub.lower().strip()
            if sub.endswith(f'.{domain}') and '*' not in sub:
                cleaned_subdomains.add(sub)
            elif sub == domain:
                continue
            elif not '.' in sub and sub != domain:
                cleaned_subdomains.add(f'{sub}.{domain}')

        return sorted(list(cleaned_subdomains))

    def _get_crt_sh_subdomains(self, domain: str) -> Set[str]:
        """Query crt.sh for certificate transparency"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=60)

            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    name_value = cert.get('name_value', '')
                    # Split by newline as some certs have multiple domains
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
        except Exception as e:
            print(f"crt.sh error: {str(e)}")

        return subdomains

    def get_securitytrails_dns_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get DNS records from SecurityTrails API"""
        url = f'https://api.securitytrails.com/v1/domain/{domain}'
        headers = {
            'APIKEY': self.securitytrails_api_key,
            'Accept': 'application/json'
        }

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            current_dns = data.get('current_dns', {})
            results = []

            for record_type, record_info in current_dns.items():
                values = record_info.get('values', [])
                for record in values:
                    # Extract common fields based on record_type
                    if record_type == 'a':
                        results.append({
                            'type': 'A',
                            'name': record.get('h') or domain,  # Use domain if host is null
                            'value': record.get('ip', ''),
                            'ttl': '',
                            'organization': record.get('ip_organization', '')
                        })
                    elif record_type == 'mx':
                        results.append({
                            'type': 'MX',
                            'name': record.get('hostname', ''),
                            'value': f"{record.get('priority', '')}",
                            'ttl': '',
                            'organization': record.get('hostname_organization', '')
                        })
                    elif record_type == 'ns':
                        results.append({
                            'type': 'NS',
                            'name': record.get('nameserver', ''),
                            'value': '',
                            'ttl': '',
                            'organization': record.get('nameserver_organization', '')
                        })
                    elif record_type == 'txt':
                        results.append({
                            'type': 'TXT',
                            'name': domain,
                            'value': record.get('value', ''),
                            'ttl': ''
                        })
                    elif record_type == 'soa':
                        results.append({
                            'type': 'SOA',
                            'name': domain,
                            'value': record.get('email', ''),
                            'ttl': record.get('ttl', '')
                        })
                    else:
                        # Generic fallback for other record types
                        results.append({
                            'type': record_type.upper(),
                            'name': domain,
                            'value': str(record),
                            'ttl': ''
                        })

            print(f"[DEBUG] SecurityTrails returned {len(results)} DNS records")
            return results

        except requests.RequestException as e:
            print(f"SecurityTrails API error: {e}")
            return []
        except Exception as e:
            print(f"SecurityTrails parsing error: {e}")
            return []