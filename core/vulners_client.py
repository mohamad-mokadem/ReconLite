import requests
import time
from typing import Dict, List, Any, Optional
import re
from config.vulnerability_config import VULNERS_API_KEY, VULNERS_TIMEOUT


class VulnersClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or VULNERS_API_KEY
        self.base_url = "https://vulners.com/api/v3"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ReconLiteV2-Scanner/2.1',
            'Content-Type': 'application/json'
        })

    def search_vulnerabilities(self, query: str, limit: int = 20) -> Dict[str, Any]:
        """Search for vulnerabilities using flexible query"""
        try:
            url = f"{self.base_url}/search/lucene/"

            payload = {
                'apikey': self.api_key,
                'query': query,
                'skip': 0,
                'size': limit,
                'fields': ['id', 'title', 'description', 'type', 'bulletinFamily',
                           'cvss', 'published', 'modified', 'href', 'sourceHref',
                           'cvelist', 'exploits']
            }

            print(f"🔍 Vulners: Searching for '{query}'")

            response = self.session.post(url, json=payload, timeout=VULNERS_TIMEOUT)
            response.raise_for_status()

            data = response.json()

            if data.get('result') == 'OK':
                results = data.get('data', {})
                vulnerabilities = results.get('search', [])

                print(f"✅ Vulners: Found {len(vulnerabilities)} vulnerabilities")
                return {
                    'success': True,
                    'total': results.get('total', 0),
                    'vulnerabilities': vulnerabilities,
                    'query': query
                }
            else:
                print(f"❌ Vulners API error: {data.get('data', 'Unknown error')}")
                return {'success': False, 'error': data.get('data', 'API error')}

        except Exception as e:
            print(f"❌ Vulners client error: {e}")
            return {'success': False, 'error': str(e)}

    def detect_software_vulnerabilities(self, banner: str, service_name: str = None) -> List[Dict[str, Any]]:
        """Detect vulnerabilities from service banner"""
        print(f"🔍 Vulners: Analyzing banner for vulnerabilities")

        detected_software = self.extract_software_from_banner(banner, service_name)
        all_vulnerabilities = []

        for software in detected_software:
            print(f"🔍 Vulners: Checking {software['name']} {software.get('version', 'unknown version')}")

            # Search for vulnerabilities
            if software.get('version'):
                results = self.search_by_software(software['name'], software['version'])
            else:
                results = self.search_by_software(software['name'])

            if results.get('success') and results.get('vulnerabilities'):
                vulnerabilities = self.process_vulnerability_results(
                    results['vulnerabilities'],
                    software
                )
                all_vulnerabilities.extend(vulnerabilities)

            time.sleep(0.1)  # Rate limiting

        # Remove duplicates and sort by severity
        unique_vulns = self.deduplicate_vulnerabilities(all_vulnerabilities)
        sorted_vulns = sorted(unique_vulns, key=lambda x: self.get_severity_score(x.get('cvss_score', 0)), reverse=True)

        print(f"✅ Vulners: Found {len(sorted_vulns)} unique vulnerabilities")
        return sorted_vulns[:20]

    def search_by_software(self, software_name: str, version: str = None) -> Dict[str, Any]:
        """Search vulnerabilities for specific software"""
        if version:
            query = f'title:"{software_name}" AND title:"{version}"'
        else:
            query = f'title:"{software_name}"'

        return self.search_vulnerabilities(query, limit=30)

    def extract_software_from_banner(self, banner: str, service_name: str = None) -> List[Dict[str, Any]]:
        """Extract software information from service banner"""
        software_list = []
        banner_lower = banner.lower()

        # Common software patterns
        patterns = {
            'apache': r'apache[\/\s]+(\d+\.\d+\.?\d*)',
            'nginx': r'nginx[\/\s]+(\d+\.\d+\.?\d*)',
            'iis': r'microsoft-iis[\/\s]+(\d+\.\d+)',
            'openssh': r'openssh[_\s]+(\d+\.\d+\.?\d*)',
            'vsftpd': r'vsftpd[\/\s]+(\d+\.\d+\.?\d*)',
            'postfix': r'postfix[\/\s]*(\d+\.\d+\.?\d*)?',
            'sendmail': r'sendmail[\/\s]+(\d+\.\d+\.?\d*)',
            'bind': r'bind[\/\s]+(\d+\.\d+\.?\d*)',
            'mysql': r'mysql[\/\s]+(\d+\.\d+\.?\d*)',
            'postgresql': r'postgresql[\/\s]+(\d+\.\d+\.?\d*)',
            'tomcat': r'tomcat[\/\s]+(\d+\.\d+\.?\d*)',
            'jetty': r'jetty[\/\s]+(\d+\.\d+\.?\d*)'
        }

        for software, pattern in patterns.items():
            match = re.search(pattern, banner_lower)
            if match:
                version = match.group(1) if match.group(1) else None
                software_list.append({
                    'name': software,
                    'version': version,
                    'confidence': 'high',
                    'detection_method': 'banner_analysis',
                    'raw_match': match.group(0)
                })

        # Add service name if no specific software detected
        if not software_list and service_name:
            software_list.append({
                'name': service_name,
                'version': None,
                'confidence': 'medium',
                'detection_method': 'service_identification'
            })

        return software_list

    def process_vulnerability_results(self, vulns: List[Dict], software: Dict) -> List[Dict[str, Any]]:
        """Process Vulners vulnerability results into standardized format"""
        processed = []

        for vuln in vulns:
            # Extract CVE IDs
            cve_list = vuln.get('cvelist', [])
            primary_cve = cve_list[0] if cve_list else vuln.get('id', 'N/A')

            # Determine severity from CVSS
            cvss_score = vuln.get('cvss', {}).get('score', 0)
            severity = self.cvss_to_severity(cvss_score)

            # Check for exploits
            exploits = vuln.get('exploits', [])
            has_exploits = len(exploits) > 0

            processed_vuln = {
                'id': primary_cve,
                'cve_id': primary_cve,
                'title': vuln.get('title', 'Unknown Vulnerability'),
                'description': vuln.get('description', 'No description available'),
                'severity': severity,
                'cvss_score': cvss_score,
                'cvss_vector': vuln.get('cvss', {}).get('vector', ''),
                'published_date': vuln.get('published', ''),
                'modified_date': vuln.get('modified', ''),
                'source': 'Vulners',
                'type': 'cve_vulnerability',
                'affected_software': software['name'],
                'software_version': software.get('version', 'Unknown'),
                'detection_method': software.get('detection_method', 'banner_analysis'),
                'confidence': software.get('confidence', 'medium'),
                'has_exploits': has_exploits,
                'exploit_count': len(exploits),
                'bulletin_family': vuln.get('bulletinFamily', ''),
                'href': vuln.get('href', ''),
                'recommendation': self.generate_recommendation(vuln, software, has_exploits)
            }

            processed.append(processed_vuln)

        return processed

    def cvss_to_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        elif cvss_score > 0.0:
            return 'Low'
        else:
            return 'Info'

    def get_severity_score(self, cvss_score: float) -> int:
        """Get numeric severity score for sorting"""
        if cvss_score >= 9.0:
            return 4
        elif cvss_score >= 7.0:
            return 3
        elif cvss_score >= 4.0:
            return 2
        elif cvss_score > 0.0:
            return 1
        else:
            return 0

    def generate_recommendation(self, vuln: Dict, software: Dict, has_exploits: bool) -> str:
        """Generate security recommendation"""
        software_name = software['name']

        if has_exploits:
            return f"URGENT: Exploits available for this vulnerability. Update {software_name} immediately to the latest version."
        elif vuln.get('cvss', {}).get('score', 0) >= 7.0:
            return f"High severity vulnerability detected. Update {software_name} to the latest secure version as soon as possible."
        else:
            return f"Update {software_name} to the latest version to address this security issue."

    def deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities based on CVE ID"""
        seen_cves = set()
        unique_vulns = []

        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id', vuln.get('id', ''))
            if cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_vulns.append(vuln)

        return unique_vulns

    def get_api_info(self) -> Dict[str, Any]:
        """Get API usage information"""
        try:
            url = f"{self.base_url}/account/audit/"
            payload = {'apikey': self.api_key}

            response = self.session.post(url, json=payload, timeout=10)
            response.raise_for_status()

            data = response.json()

            if data.get('result') == 'OK':
                return {
                    'success': True,
                    'quota_info': data.get('data', {})
                }
            else:
                return {'success': False, 'error': 'Could not get API info'}

        except Exception as e:
            return {'success': False, 'error': str(e)}