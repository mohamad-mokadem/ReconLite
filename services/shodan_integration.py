# services/shodan_integration.py

from datetime import datetime
from typing import Dict, Any, List, Optional

import shodan


class ShodanIntegration:
    """Enhanced Shodan integration for ReconLite Scanner Manager"""

    def __init__(self, api_key: Optional[str] = None, enabled: bool = True):
        self.enabled = enabled
        self.api_key = api_key
        self.api = None
        self.available = False

        if self.enabled and api_key:
            try:
                self.api = shodan.Shodan(api_key)
                # Test API key
                self.api.info()
                self.available = True
                print("✅ Shodan Scanner integration enabled and API key validated")
            except shodan.APIError as e:
                print(f"❌ Shodan API error: {e}")
                self.available = False
            except Exception as e:
                print(f"❌ Shodan initialization failed: {e}")
                self.available = False
        else:
            print("⚠️ Shodan Scanner integration disabled (no API key provided)")

    def enhance_scan_with_shodan(self, ip: str, port: int, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced scan with Shodan intelligence and database storage"""
        if not self.available:
            scan_results['shodan_intelligence'] = {
                'available': False,
                'error': 'Shodan not available'
            }
            return scan_results

        try:
            print(f"🔍 Shodan: Enhancing scan results for {ip}:{port}")

            # Get Shodan data for this specific IP
            shodan_data = self._get_shodan_host_info(ip)

            if not shodan_data:
                scan_results['shodan_intelligence'] = {
                    'available': True,
                    'host_found': False,
                    'message': 'No Shodan data found for this host'
                }
                return scan_results

            # SAVE SHODAN DATA TO DATABASE
            session_id = scan_results.get('session_id')
            if session_id:
                self._save_shodan_data_to_db(session_id, ip, port, shodan_data)

            # Extract relevant data for this specific port
            port_data = self._extract_port_data(shodan_data, port)

            # Enhance the scan results
            enhanced_results = self._merge_shodan_data(scan_results, shodan_data, port_data)

            print(f"✅ Shodan: Enhanced scan results with Shodan intelligence and saved to DB")
            return enhanced_results

        except Exception as e:
            print(f"❌ Shodan enhancement error: {e}")
            scan_results['shodan_intelligence'] = {
                'available': True,
                'error': str(e)
            }
            return scan_results

    def _save_shodan_data_to_db(self, session_id: str, ip: str, target_port: int, shodan_data: Dict[str, Any]):
        """Save Shodan data to database"""
        try:
            # Import database here to avoid circular imports
            from database import db

            print(f"💾 Saving Shodan data to database for {ip}:{target_port}")

            # 1. Save host intelligence
            db.save_shodan_host_intelligence(session_id, ip, shodan_data)

            # 2. Save port-specific data for the target port
            target_port_data = self._extract_port_data(shodan_data, target_port)
            if target_port_data:
                db.save_shodan_port_data(session_id, ip, target_port_data)

            # 3. Save other ports found by Shodan
            other_ports = []
            for service in shodan_data.get('data', []):
                if service.get('port') != target_port:
                    other_ports.append({
                        'port': service.get('port'),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'last_seen': service.get('timestamp', '')
                    })

            if other_ports:
                db.save_shodan_other_ports(session_id, ip, other_ports)

            # 4. Update session metadata
            db.update_session_shodan_metadata(session_id, credits_used=1)

            print(f"✅ Shodan data saved to database successfully")

        except Exception as e:
            print(f"❌ Error saving Shodan data to database: {e}")

    def get_pre_scan_intelligence(self, target: str, target_type: str) -> Dict[str, Any]:
        """Get pre-scan intelligence from Shodan to optimize scanning"""
        if not self.available:
            return {'available': False, 'open_ports': [], 'services': []}

        try:
            print(f"🔍 Shodan: Getting pre-scan intelligence for {target}")

            if target_type == 'domain':
                # Search by hostname
                query = f"hostname:{target}"
            else:
                # Search by IP or network
                query = f"net:{target}" if '/' in target else target

            # Search Shodan
            results = self.api.search(query, limit=100)

            # Extract intelligence
            intelligence = self._parse_pre_scan_data(results)
            intelligence['query_used'] = query
            intelligence['total_results'] = results['total']

            print(f"✅ Shodan: Found {len(intelligence['open_ports'])} open ports from pre-scan")
            return intelligence

        except Exception as e:
            print(f"❌ Shodan pre-scan error: {e}")
            return {'available': False, 'error': str(e), 'open_ports': [], 'services': []}

    def _get_shodan_host_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get detailed host information from Shodan"""
        try:
            host_info = self.api.host(ip)
            return host_info
        except shodan.APIError as e:
            if "No information available" in str(e):
                return None
            print(f"❌ Shodan API error for {ip}: {e}")
            return None
        except Exception as e:
            print(f"❌ Shodan host lookup error: {e}")
            return None

    def _extract_port_data(self, shodan_data: Dict[str, Any], target_port: int) -> Optional[Dict[str, Any]]:
        """Extract data for specific port from Shodan results"""
        for service in shodan_data.get('data', []):
            if service.get('port') == target_port:
                return service
        return None

    def _parse_pre_scan_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Shodan search results for pre-scan intelligence"""
        intelligence = {
            'available': True,
            'open_ports': [],
            'services': {},
            'hosts': [],
            'technologies': set(),
            'countries': set(),
            'organizations': set(),
            'timestamps': []
        }

        for item in results.get('matches', []):
            ip = item.get('ip_str')
            port = item.get('port')

            if ip and port:
                # Track unique ports
                if port not in intelligence['open_ports']:
                    intelligence['open_ports'].append(port)

                # Track services per port
                service = item.get('product', 'unknown')
                version = item.get('version', '')
                if port not in intelligence['services']:
                    intelligence['services'][port] = []

                service_info = {
                    'ip': ip,
                    'service': service,
                    'version': version,
                    'banner': item.get('banner', '').strip()[:100],  # Limit banner length
                    'org': item.get('org', ''),
                    'country': item.get('location', {}).get('country_name', ''),
                    'last_seen': item.get('timestamp', '')
                }
                intelligence['services'][port].append(service_info)

                # Track technologies
                if service and service != 'unknown':
                    intelligence['technologies'].add(service)

                # Track countries
                country = item.get('location', {}).get('country_name', '')
                if country:
                    intelligence['countries'].add(country)

                # Track organizations
                org = item.get('org', '')
                if org:
                    intelligence['organizations'].add(org)

                # Track timestamps
                timestamp = item.get('timestamp', '')
                if timestamp:
                    intelligence['timestamps'].append(timestamp)

        # Convert sets to lists for JSON serialization
        intelligence['technologies'] = list(intelligence['technologies'])
        intelligence['countries'] = list(intelligence['countries'])
        intelligence['organizations'] = list(intelligence['organizations'])
        intelligence['open_ports'] = sorted(intelligence['open_ports'])

        return intelligence

    def _merge_shodan_data(self, scan_results: Dict[str, Any], shodan_data: Dict[str, Any],
                           port_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge Shodan data with existing scan results"""

        # Add Shodan intelligence section with enhanced data
        scan_results['shodan_intelligence'] = {
            'available': True,
            'host_found': True,
            'last_update': shodan_data.get('last_update', ''),
            'scan_time': datetime.now().isoformat(),
            'saved_to_database': True,  # NEW: Indicate data is saved
            'host_summary': {
                'ip': shodan_data.get('ip_str', ''),
                'hostnames': shodan_data.get('hostnames', []),
                'domains': shodan_data.get('domains', []),
                'country': shodan_data.get('country_name', ''),
                'city': shodan_data.get('city', ''),
                'org': shodan_data.get('org', ''),
                'asn': shodan_data.get('asn', ''),
                'isp': shodan_data.get('isp', ''),
                'total_ports': len(shodan_data.get('data', []))
            }
        }

        # If we have specific port data, enhance the scan results
        if port_data:
            enhanced_service_info = {
                'shodan_product': port_data.get('product', ''),
                'shodan_version': port_data.get('version', ''),
                'shodan_banner': port_data.get('banner', '').strip(),
                'shodan_timestamp': port_data.get('timestamp', ''),
                'shodan_ssl': port_data.get('ssl', {}),
                'shodan_http': port_data.get('http', {}),
                'shodan_cpe': port_data.get('cpe', [])
            }

            # Merge with existing service info
            if 'service_info' not in scan_results:
                scan_results['service_info'] = {}
            scan_results['service_info'].update(enhanced_service_info)

            # Add Shodan-specific vulnerabilities if found
            if port_data.get('vulns'):
                shodan_vulns = []
                for vuln_id in port_data.get('vulns', []):
                    shodan_vulns.append({
                        'id': vuln_id,
                        'type': 'shodan_vulnerability',
                        'severity': 'High',  # Default, could be refined
                        'title': f'Shodan Detected Vulnerability: {vuln_id}',
                        'description': f'Vulnerability {vuln_id} detected by Shodan scan',
                        'recommendation': f'Investigate and patch vulnerability {vuln_id}',
                        'source': 'Shodan',
                        'detected_date': port_data.get('timestamp', '')
                    })

                if 'vulnerabilities' not in scan_results:
                    scan_results['vulnerabilities'] = []
                scan_results['vulnerabilities'].extend(shodan_vulns)

            # Add port-specific intelligence
            scan_results['shodan_intelligence']['port_data'] = {
                'port': port_data.get('port'),
                'product': port_data.get('product', ''),
                'version': port_data.get('version', ''),
                'banner_hash': port_data.get('hash', ''),
                'ssl_info': port_data.get('ssl', {}),
                'http_info': port_data.get('http', {}),
                'vulnerabilities': list(port_data.get('vulns', [])),
                'last_seen': port_data.get('timestamp', '')
            }

        # Add all other ports found by Shodan for this host (limited for UI)
        other_ports = []
        for service in shodan_data.get('data', []):
            if service.get('port') != scan_results.get('port'):
                other_ports.append({
                    'port': service.get('port'),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'last_seen': service.get('timestamp', '')
                })

        scan_results['shodan_intelligence']['other_ports'] = other_ports[:10]  # Limit to 10

        return scan_results

    def get_recommended_scan_targets(self, intelligence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get recommended scan targets based on Shodan intelligence"""
        if not intelligence.get('available'):
            return []

        recommendations = []

        # High-value ports to prioritize
        high_value_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
                            3389, 5432, 3306, 1433, 445, 139, 161, 389, 636]

        for port in intelligence.get('open_ports', []):
            priority = 'High' if port in high_value_ports else 'Medium'

            # Get service info for this port
            services = intelligence.get('services', {}).get(port, [])

            recommendation = {
                'port': port,
                'priority': priority,
                'reason': self._get_scan_reason(port, services),
                'expected_service': self._get_expected_service(port),
                'shodan_services': [s['service'] for s in services if s['service'] != 'unknown'],
                'host_count': len(services)
            }

            recommendations.append(recommendation)

        # Sort by priority and port number
        recommendations.sort(key=lambda x: (x['priority'] == 'Medium', x['port']))

        return recommendations

    def _get_scan_reason(self, port: int, services: List[Dict[str, Any]]) -> str:
        """Get reason why this port should be scanned"""
        common_reasons = {
            21: "FTP service - check for anonymous access",
            22: "SSH service - check for weak authentication",
            23: "Telnet service - inherently insecure",
            25: "SMTP service - check for open relay",
            53: "DNS service - check for zone transfer",
            80: "HTTP service - web application testing",
            443: "HTTPS service - SSL/TLS analysis",
            445: "SMB service - check for file sharing vulnerabilities",
            3389: "RDP service - check for weak authentication",
            3306: "MySQL service - database security check",
            5432: "PostgreSQL service - database security check"
        }

        if port in common_reasons:
            return common_reasons[port]

        if services:
            unique_services = set(s['service'] for s in services if s['service'] != 'unknown')
            if unique_services:
                return f"Active {'/'.join(unique_services)} service detected"

        return "Open port detected by Shodan"

    def _get_expected_service(self, port: int) -> str:
        """Get expected service for a port"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"
        }
        return common_services.get(port, "Unknown")

    def get_shodan_statistics(self) -> Dict[str, Any]:
        """Get Shodan API usage statistics"""
        if not self.available:
            return {'available': False}

        try:
            info = self.api.info()
            return {
                'available': True,
                'credits_used': info.get('query_credits', 0),
                'credits_remaining': info.get('plan', 'unknown'),
                'scan_credits': info.get('scan_credits', 0),
                'monitored_ips': info.get('monitored_ips', 0),
                'unlocked_left': info.get('unlocked_left', 0)
            }
        except Exception as e:
            return {'available': True, 'error': str(e)}

    def is_available(self) -> bool:
        """Check if Shodan integration is available"""
        return self.available

    def test_connection(self) -> Dict[str, Any]:
        """Test Shodan connection and API key"""
        if not self.enabled:
            return {'success': False, 'error': 'Shodan integration disabled'}

        if not self.api_key:
            return {'success': False, 'error': 'No Shodan API key provided'}

        try:
            info = self.api.info()
            return {
                'success': True,
                'message': 'Shodan connection successful',
                'plan': info.get('plan', 'unknown'),
                'credits': info.get('query_credits', 0)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}


# Integration with existing ScannerManager
def integrate_shodan_with_scanner_manager():
    """Integration example for your existing ScannerManager"""

    # Add this to your services/__init__.py imports
    from .shodan_integration import ShodanIntegration

    # Modify your ScannerManager class to include Shodan
    def enhanced_scan_service(ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Enhanced scan_service with Shodan integration"""

        # Your existing scan logic
        from . import scanner_manager
        results = scanner_manager.scan_service(ip, port, **kwargs)

        # Add Shodan enhancement if enabled
        enable_shodan = kwargs.get('enable_shodan', True)
        shodan_api_key = kwargs.get('shodan_api_key', 'ddslzZF15TbQBRK6oWbd9OtUKk0LGGEo')

        if enable_shodan and shodan_api_key:
            shodan_integration = ShodanScannerIntegration(shodan_api_key)
            results = shodan_integration.enhance_scan_with_shodan(ip, port, results)

        return results

    return enhanced_scan_service


