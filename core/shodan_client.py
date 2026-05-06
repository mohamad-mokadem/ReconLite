import shodan
from typing import List, Dict, Any


class ShodanClient:
    """Shodan API client for additional port and service discovery"""

    def __init__(self, api_key: str):
        self.api = shodan.Shodan(api_key)

    def search_target(self, target: str, target_type: str) -> List[Dict[str, Any]]:
        """Search Shodan for ports and services on target"""
        try:
            if target_type == 'domain':
                # For domains, search by hostname
                query = f"hostname:{target}"
            else:
                # For IP ranges, search by net
                query = f"net:{target}"

            # Search Shodan
            results = self.api.search(query, limit=50)

            return self._parse_shodan_results(results)

        except shodan.APIError as e:
            print(f"Shodan API error: {str(e)}")
            return []
        except Exception as e:
            print(f"Shodan search error: {str(e)}")
            return []

    def _parse_shodan_results(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Shodan search results"""
        parsed_results = []
        seen = set()

        for item in results['matches']:
            try:
                ip = item.get('ip_str', '')
                port = item.get('port', 0)

                if not ip or not port:
                    continue

                key = f"{ip}:{port}"
                if key in seen:
                    continue
                seen.add(key)

                # Extract location info
                location = item.get('location', {})

                parsed_results.append({
                    "ip": ip,
                    "port": port,
                    "protocol": item.get('transport', 'tcp'),
                    "service": item.get('product', 'unknown'),
                    "version": item.get('version', ''),
                    "banner": item.get('banner', '').strip(),
                    "http_title": item.get('http', {}).get('title', ''),
                    "http_server": item.get('http', {}).get('server', ''),
                    "http_status": '',
                    "asn": f"AS{item.get('asn', '')}" if item.get('asn') else '',
                    "country": location.get('country_name', ''),
                    "org": item.get('org', ''),
                    "source": "Shodan",
                    "timestamp": item.get('timestamp', '')
                })

            except Exception as e:
                print(f"Error parsing Shodan result: {e}")
                continue

        print(f"[DEBUG] Parsed {len(parsed_results)} Shodan results")
        return parsed_results