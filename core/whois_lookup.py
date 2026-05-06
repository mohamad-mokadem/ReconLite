import whois
from datetime import datetime
from typing import Dict, Any, Union, List


class WhoisLookup:
    """Whois domain information lookup"""

    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive whois information for a domain"""
        try:
            w = whois.whois(domain)

            # Handle both single values and lists
            def safe_extract(value: Union[str, List, None]) -> str:
                if isinstance(value, list):
                    return value[0] if value else ''
                return str(value) if value else ''

            # Extract and format whois data
            whois_data = {
                'domain_name': safe_extract(w.domain_name),
                'registrar': safe_extract(w.registrar),
                'creation_date': self._format_date(w.creation_date),
                'expiration_date': self._format_date(w.expiration_date),
                'updated_date': self._format_date(w.updated_date),
                'name_servers': self._extract_nameservers(w.name_servers),
                'status': self._extract_status(w.status),
                'country': safe_extract(w.country),
                'registrant_org': safe_extract(w.org),
                'admin_email': safe_extract(w.emails[0] if w.emails else ''),
                'whois_server': safe_extract(w.whois_server)
            }

            # Calculate domain age if creation date available
            if whois_data['creation_date']:
                try:
                    if isinstance(w.creation_date, list):
                        created = w.creation_date[0]
                    else:
                        created = w.creation_date

                    if created:
                        age_days = (datetime.now() - created).days
                        whois_data['domain_age_days'] = age_days
                        whois_data['domain_age_years'] = round(age_days / 365.25, 1)
                except:
                    pass

            return whois_data

        except Exception as e:
            print(f"Whois lookup error for {domain}: {str(e)}")
            return {}

    def _format_date(self, date_value: Union[datetime, List, str, None]) -> str:
        """Format date value safely"""
        if not date_value:
            return ''

        try:
            if isinstance(date_value, list):
                date_value = date_value[0]

            if hasattr(date_value, 'strftime'):
                return date_value.strftime('%Y-%m-%d %H:%M:%S')
            return str(date_value)
        except:
            return str(date_value) if date_value else ''

    def _extract_nameservers(self, ns_value: Union[List, str, None]) -> List[str]:
        """Extract and clean nameserver list"""
        if not ns_value:
            return []

        if isinstance(ns_value, list):
            return [ns.lower().rstrip('.') for ns in ns_value if ns]
        return [str(ns_value).lower().rstrip('.')]

    def _extract_status(self, status_value: Union[List, str, None]) -> List[str]:
        """Extract domain status information"""
        if not status_value:
            return []

        if isinstance(status_value, list):
            return status_value
        return [str(status_value)]