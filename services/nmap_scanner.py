import subprocess
import json
import re
import time
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime

# Safe imports with fallbacks
try:
    import nmap

    NMAP_AVAILABLE = True
except ImportError:
    print("❌ python-nmap not installed. Run: pip install python-nmap")
    NMAP_AVAILABLE = False
    nmap = None

try:
    from config.vulnerability_config import VULNERS_API_KEY
except ImportError:
    print("⚠️ Could not import VULNERS_API_KEY from config")
    VULNERS_API_KEY = None


class NmapScanner:
    """Enhanced nmap scanner with NSE scripts and Vulners integration for passive discovery"""

    def __init__(self):
        self.nm = None
        self.available = False
        self.vulners_api_key = VULNERS_API_KEY
        self.nse_scripts = self._load_nse_categories()

        # Initialize with comprehensive checks
        if NMAP_AVAILABLE:
            self.available = self._initialize_nmap()
        else:
            print("❌ Cannot initialize nmap: python-nmap library not available")

    def _initialize_nmap(self) -> bool:
        """Initialize nmap scanner with comprehensive checks"""
        try:
            # Check if nmap binary exists
            if not self._check_nmap_binary():
                return False

            # Try to create PortScanner
            self.nm = nmap.PortScanner()

            # Test basic functionality
            if not self._test_basic_functionality():
                return False

            print("✅ Enhanced Nmap initialized successfully")
            return True

        except Exception as e:
            print(f"❌ Failed to initialize nmap: {e}")
            return False

    def _check_nmap_binary(self) -> bool:
        """Check if nmap binary is available and working"""
        try:
            result = subprocess.run(['nmap', '--version'],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(
                    f"✅ Nmap binary found: {result.stdout.split()[2] if len(result.stdout.split()) > 2 else 'unknown version'}")
                return True
            else:
                print(f"❌ Nmap binary error: {result.stderr}")
                return False
        except FileNotFoundError:
            print("❌ Nmap binary not found in PATH")
            print("💡 Install nmap for your OS:")
            print("   - Windows: https://nmap.org/download.html")
            print("   - macOS: brew install nmap")
            print("   - Linux: sudo apt-get install nmap (Ubuntu) or sudo yum install nmap (CentOS)")
            return False
        except subprocess.TimeoutExpired:
            print("❌ Nmap binary check timed out")
            return False
        except Exception as e:
            print(f"❌ Unexpected error checking nmap binary: {e}")
            return False

    def _test_basic_functionality(self) -> bool:
        """Test basic nmap functionality"""
        try:
            # Try to get nmap version through library
            version = self.nm.nmap_version()
            print(f"✅ Nmap library version: {version}")

            # Try a simple scan to localhost (should be safe)
            test_result = self.nm.scan('127.0.0.1', '80', arguments='-sn', timeout=5)
            print("✅ Basic nmap functionality test passed")
            return True

        except Exception as e:
            print(f"❌ Basic functionality test failed: {e}")
            return False

    def _load_nse_categories(self) -> Dict[str, List[str]]:
        """Load NSE script categories for comprehensive scanning"""
        return {
            'discovery': [
                'banner', 'version', 'discovery', 'safe', 'default'
            ],
            'vulnerability': [
                'vuln', 'vulners'  # Key scripts for vulnerability detection
            ],
            'service_specific': {
                'http': ['http-*', 'ssl-*'],
                'ssh': ['ssh-*'],
                'ftp': ['ftp-*'],
                'smtp': ['smtp-*'],
                'smb': ['smb-*'],
                'snmp': ['snmp-*'],
                'mysql': ['mysql-*'],
                'ssl': ['ssl-*', 'tls-*']
            }
        }

    def passive_port_discovery(self, target: str, port_range: str = "1-1000", enable_vulners: bool = True) -> Dict[
        str, Any]:
        """
        FIXED: Passive port discovery using enhanced nmap with NSE scripts

        Args:
            target: Target IP/domain to scan
            port_range: Port range to scan (e.g., "1-1000")
            enable_vulners: Whether to enable Vulners NSE script

        Returns:
            Dictionary with comprehensive scan results
        """
        if not self.available:
            return {
                'error': 'Enhanced nmap scanner not available',
                'suggestions': [
                    'Install nmap: sudo apt-get install nmap (Linux) or brew install nmap (macOS)',
                    'Install python-nmap: pip install python-nmap',
                    'Check nmap binary is in PATH'
                ]
            }

        try:
            print(f"🔍 Starting passive discovery with nmap NSE for {target}")
            print(f"🎯 Port range: {port_range}, Vulners enabled: {enable_vulners}")

            scan_start_time = time.time()

            # Build scan arguments with optional Vulners integration
            arguments = self._build_passive_scan_arguments_with_vulners(enable_vulners)

            # Perform the scan
            print(f"🚀 Executing nmap scan: nmap {arguments} -p {port_range} {target}")
            self.nm.scan(target, port_range, arguments=arguments, timeout=300)

            if target not in self.nm.all_hosts():
                return {
                    'error': f'Target {target} not responsive or reachable',
                    'suggestions': [
                        'Check if target IP/domain is correct',
                        'Verify network connectivity to target',
                        'Target may be behind firewall blocking ICMP',
                        'Try with different timing options (-T4 or -T2)'
                    ]
                }

            # Extract comprehensive results
            scan_duration = time.time() - scan_start_time

            # Get discovered ports
            discovered_ports = self._extract_discovered_ports(target)

            # Get host information
            host_info = self._extract_host_info(target)

            # Get OS detection if available
            os_detection = self._extract_os_info(target)

            # Extract vulnerabilities (including Vulners if enabled)
            vulnerabilities = self._extract_vulnerabilities_with_vulners(target, enable_vulners)

            # Separate CVE vulnerabilities from Vulners
            cve_vulnerabilities = [v for v in vulnerabilities if v.get('source') == 'vulners_nse']
            other_vulnerabilities = [v for v in vulnerabilities if v.get('source') != 'vulners_nse']

            # Build comprehensive results
            results = {
                'target': target,
                'scan_time': datetime.now().isoformat(),
                'scan_duration': round(scan_duration, 2),
                'discovered_ports': discovered_ports,
                'host_info': host_info,
                'os_detection': os_detection,
                'vulnerabilities': other_vulnerabilities,
                'cve_vulnerabilities': cve_vulnerabilities,  # Separate CVE findings from Vulners
                'scan_stats': {
                    'total_ports_scanned': len(port_range.split('-')) if '-' in port_range else 1,
                    'open_ports_found': len([p for p in discovered_ports if p.get('state') == 'open']),
                    'vulnerabilities_found': len(vulnerabilities),
                    'cve_vulnerabilities_found': len(cve_vulnerabilities),
                    'scan_duration_seconds': round(scan_duration, 2)
                },
                'enhanced_features': {
                    'nse_scripts_used': True,
                    'vulners_integration': enable_vulners and bool(self.vulners_api_key),
                    'vulnerability_detection': len(vulnerabilities) > 0,
                    'scan_duration': scan_duration
                }
            }

            print(f"✅ Passive discovery completed successfully")
            print(f"📊 Found {len(discovered_ports)} services, {len(vulnerabilities)} vulnerabilities")
            print(f"🛡️ CVE vulnerabilities from Vulners: {len(cve_vulnerabilities)}")

            return results

        except Exception as e:
            error_msg = str(e)
            print(f"❌ Passive discovery failed: {error_msg}")

            return {
                'error': f'Passive discovery failed: {error_msg}',
                'target': target,
                'suggestions': [
                    'Check if target is reachable (ping test)',
                    'Verify nmap has necessary permissions (may need sudo)',
                    'Try with a smaller port range for testing',
                    'Check firewall settings on scanning machine',
                    'Ensure target allows port scanning (if you own it)'
                ]
            }

    def comprehensive_vulnerability_scan(self, target: str, port: int, service_type: str = None) -> Dict[str, Any]:
        """Enhanced vulnerability scanning for a specific port"""
        if not self.available:
            return {'error': 'Nmap not available - check installation'}

        try:
            print(f"🛡️ Starting comprehensive vulnerability scan: {target}:{port}")

            # Select appropriate NSE scripts
            vuln_scripts = self._select_vulnerability_scripts(service_type)

            # Build comprehensive scan command
            script_args = ','.join(vuln_scripts)
            arguments = f"--script {script_args}"

            # Add Vulners integration
            if self.vulners_api_key:
                arguments += f" --script-args=vulners.api-key={self.vulners_api_key}"

            # Add timing and detection options
            arguments += " -sV --version-intensity 9 -T3"

            self.nm.scan(target, str(port), arguments=arguments, timeout=120)

            if target not in self.nm.all_hosts():
                return {'error': 'Host not responsive'}

            if port not in self.nm[target].get('tcp', {}):
                return {'error': f'Port {port} not accessible'}

            # Extract comprehensive results
            port_info = self.nm[target]['tcp'][port]
            script_results = port_info.get('script', {})

            # Parse all vulnerability findings
            vulnerabilities = self._parse_comprehensive_vulnerabilities(script_results, target, port)

            # Enhance with additional Vulners data if needed
            enhanced_vulns = self._enhance_with_vulners_api(vulnerabilities, target, port, service_type)

            results = {
                'target': f"{target}:{port}",
                'service': port_info.get('name', 'unknown'),
                'version': port_info.get('version', ''),
                'product': port_info.get('product', ''),
                'state': port_info.get('state', 'unknown'),
                'nse_scripts_run': vuln_scripts,
                'script_results': script_results,
                'vulnerabilities': enhanced_vulns,
                'exploit_info': self._extract_exploit_info(enhanced_vulns),
                'risk_assessment': self._assess_risk(enhanced_vulns),
                'scan_metadata': {
                    'scan_time': datetime.now().isoformat(),
                    'scripts_executed': len(script_results),
                    'vulnerabilities_found': len(enhanced_vulns),
                    'vulners_integrated': bool(self.vulners_api_key)
                }
            }

            print(f"✅ Comprehensive scan completed: {len(enhanced_vulns)} vulnerabilities found")
            return results

        except Exception as e:
            return {'error': f'Comprehensive vulnerability scan failed: {str(e)}'}

    def _build_passive_scan_arguments_with_vulners(self, enable_vulners: bool = True) -> str:
        """Build nmap scan arguments for passive discovery with optional Vulners"""
        print(f"🔧 Building scan arguments with Vulners: {enable_vulners}")

        # Base arguments for passive discovery
        arguments = "-sS -sV -sC --version-intensity 6 -T3"

        # Add basic vulnerability detection scripts
        arguments += " --script=default,vuln"

        # Add Vulners script only if enabled and API key is available
        if enable_vulners and self.vulners_api_key:
            arguments += ",vulners"
            arguments += f" --script-args=vulners.api-key={self.vulners_api_key}"
            print("✅ Vulners NSE script added to passive scan")
        else:
            if not enable_vulners:
                print("⚠️ Vulners NSE script disabled by user preference")
            elif not self.vulners_api_key:
                print("⚠️ Vulners NSE script disabled - no API key configured")

        print(f"🎯 Final nmap arguments: {arguments}")
        return arguments

    def _extract_host_info(self, target: str) -> Dict[str, Any]:
        """Extract comprehensive host information"""
        try:
            host = self.nm[target]
            return {
                'ip': target,
                'hostname': host.hostname(),
                'state': host.state(),
                'protocols': list(host.all_protocols()),
                'uptime': host.get('uptime', {}),
                'last_boot': host.get('lastboot', 'unknown')
            }
        except Exception as e:
            print(f"⚠️ Error extracting host info: {e}")
            return {'ip': target, 'error': str(e)}

    def _extract_discovered_ports(self, target: str) -> List[Dict[str, Any]]:
        """Extract all discovered ports with enhanced information"""
        discovered_ports = []

        try:
            for protocol in self.nm[target].all_protocols():
                ports = self.nm[target][protocol]

                for port, port_data in ports.items():
                    port_info = {
                        'port': port,
                        'protocol': protocol,
                        'state': port_data.get('state', 'unknown'),
                        'service': port_data.get('name', 'unknown'),
                        'product': port_data.get('product', ''),
                        'version': port_data.get('version', ''),
                        'extrainfo': port_data.get('extrainfo', ''),
                        'confidence': port_data.get('conf', 0),
                        'cpe': port_data.get('cpe', []),
                        'scripts': port_data.get('script', {}),
                        'banner': self._extract_banner_from_scripts(port_data.get('script', {}))
                    }
                    discovered_ports.append(port_info)
        except Exception as e:
            print(f"⚠️ Error extracting ports: {e}")

        return discovered_ports

    def _extract_os_info(self, target: str) -> Dict[str, Any]:
        """Extract OS detection information"""
        try:
            host = self.nm[target]
            return {
                'osmatch': host.get('osmatch', []),
                'osclass': host.get('osclass', []),
                'portused': host.get('portused', []),
                'fingerprint': host.get('fingerprint', '')
            }
        except Exception as e:
            print(f"⚠️ Error extracting OS info: {e}")
            return {}

    def _extract_vulnerabilities_with_vulners(self, target: str, vulners_enabled: bool = True) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from all scanned ports, including Vulners results"""
        all_vulnerabilities = []

        try:
            print(f"🔍 Extracting vulnerabilities for {target} (Vulners: {vulners_enabled})")

            for protocol in self.nm[target].all_protocols():
                ports = self.nm[target][protocol]

                for port, port_data in ports.items():
                    script_results = port_data.get('script', {})
                    print(f"📊 Port {port} has {len(script_results)} script results")

                    # Parse vulnerabilities from all NSE scripts
                    port_vulns = self._parse_comprehensive_vulnerabilities(
                        script_results, target, port, include_vulners=vulners_enabled
                    )
                    all_vulnerabilities.extend(port_vulns)
                    print(f"🛡️ Port {port} contributed {len(port_vulns)} vulnerabilities")

        except Exception as e:
            print(f"⚠️ Error extracting vulnerabilities: {e}")

        print(f"🎯 Total vulnerabilities extracted: {len(all_vulnerabilities)}")
        return all_vulnerabilities

    def _parse_comprehensive_vulnerabilities(self, script_results: Dict[str, str],
                                             target: str, port: int, include_vulners: bool = True) -> List[
        Dict[str, Any]]:
        """Parse comprehensive vulnerability results from NSE scripts"""
        vulnerabilities = []

        print(f"🔍 Parsing {len(script_results)} NSE scripts for port {port}")

        for script_name, output in script_results.items():
            try:
                print(f"📝 Processing script: {script_name}")

                # Parse Vulners script output (primary source for CVEs)
                if script_name == 'vulners' and include_vulners:
                    vulners_vulns = self._parse_vulners_nse_output(output, target, port)
                    vulnerabilities.extend(vulners_vulns)
                    print(f"🛡️ Vulners script found {len(vulners_vulns)} CVE vulnerabilities")

                # Parse other vulnerability scripts
                elif 'vuln' in script_name and script_name != 'vulners':
                    script_vulns = self._parse_nse_vulnerability_script(script_name, output, target, port)
                    vulnerabilities.extend(script_vulns)
                    print(f"🎯 Script {script_name} found {len(script_vulns)} vulnerabilities")

                # Parse service-specific vulnerability scripts
                elif any(x in script_name for x in ['http-vuln', 'smb-vuln', 'ssh-vuln', 'ssl-']):
                    service_vulns = self._parse_service_vulnerability_script(script_name, output, target, port)
                    vulnerabilities.extend(service_vulns)
                    print(f"🔧 Service script {script_name} found {len(service_vulns)} vulnerabilities")

            except Exception as e:
                print(f"⚠️ Error parsing script {script_name}: {e}")

        return vulnerabilities

    def _parse_vulners_nse_output(self, output: str, target: str = None, port: int = None) -> List[Dict[str, Any]]:
        """Parse vulners NSE script output for CVE vulnerabilities"""
        vulnerabilities = []

        try:
            print(f"🔍 Parsing Vulners NSE output for {target}:{port}")
            print(f"📝 Raw Vulners output (first 200 chars): {output[:200]}...")

            # Pattern 1: CVE entries with CVSS scores and URLs
            # Example: CVE-2021-44228    9.3    https://vulners.com/cve/CVE-2021-44228
            cve_pattern = r'(CVE-\d{4}-\d+)\s+(\d+\.\d+)\s+(https?://[^\s]+)'
            cve_matches = re.findall(cve_pattern, output)

            # Pattern 2: Simpler CVE pattern without URLs
            # Example: CVE-2021-44228    9.3
            if not cve_matches:
                simple_cve_pattern = r'(CVE-\d{4}-\d+).*?(\d+\.\d+)'
                simple_matches = re.findall(simple_cve_pattern, output)
                cve_matches = [(match[0], match[1], f"https://vulners.com/cve/{match[0]}")
                               for match in simple_matches]

            # Pattern 3: Just CVE IDs (fallback)
            if not cve_matches:
                cve_id_pattern = r'(CVE-\d{4}-\d+)'
                cve_ids = re.findall(cve_id_pattern, output)
                cve_matches = [(cve_id, "0.0", f"https://vulners.com/cve/{cve_id}")
                               for cve_id in cve_ids]

            print(f"🎯 Found {len(cve_matches)} CVE matches in Vulners output")

            for cve_id, cvss_score, url in cve_matches:
                try:
                    cvss_score = float(cvss_score) if cvss_score != "0.0" else None

                    vuln = {
                        'id': cve_id,
                        'cve_id': cve_id,
                        'type': 'cve_vulnerability',
                        'source': 'vulners_nse',
                        'severity': self._cvss_to_severity(cvss_score) if cvss_score else 'Info',
                        'cvss_score': cvss_score,
                        'title': f'CVE Vulnerability: {cve_id}',
                        'description': f'CVE {cve_id} detected via Vulners NSE script' + (
                            f' (CVSS: {cvss_score})' if cvss_score else ''),
                        'recommendation': f'Apply security patches for {cve_id}. Review vendor advisories.',
                        'href': url,
                        'exploit_available': 'exploit' in output.lower(),
                        'detection_method': 'vulners_nse_script',
                        'port': port,
                        'target': target,
                        'script_output': output[:200] + '...' if len(output) > 200 else output
                    }
                    vulnerabilities.append(vuln)
                    print(f"✅ Added CVE {cve_id} (CVSS: {cvss_score}, Severity: {vuln['severity']})")

                except ValueError as e:
                    print(f"⚠️ Error parsing CVSS score for {cve_id}: {e}")
                    # Add with unknown CVSS
                    vuln = {
                        'id': cve_id,
                        'cve_id': cve_id,
                        'type': 'cve_vulnerability',
                        'source': 'vulners_nse',
                        'severity': 'Info',
                        'cvss_score': None,
                        'title': f'CVE Vulnerability: {cve_id}',
                        'description': f'CVE {cve_id} detected via Vulners NSE script',
                        'recommendation': f'Apply security patches for {cve_id}',
                        'href': url,
                        'detection_method': 'vulners_nse_script',
                        'port': port,
                        'target': target
                    }
                    vulnerabilities.append(vuln)

        except Exception as e:
            print(f"❌ Error parsing Vulners NSE output: {e}")
            print(f"🔍 Debug - Raw output: {output}")

        return vulnerabilities

    def _parse_nse_vulnerability_script(self, script_name: str, output: str, target: str = None, port: int = None) -> \
    List[Dict[str, Any]]:
        """Parse general NSE vulnerability script output"""
        vulnerabilities = []

        try:
            if 'VULNERABLE' in output or 'CVE-' in output:
                # Extract CVE references
                cve_matches = re.findall(r'CVE-\d{4}-\d+', output)

                if cve_matches:
                    for cve_id in cve_matches:
                        vuln = {
                            'id': cve_id,
                            'type': 'cve',
                            'source': 'nmap-nse',
                            'severity': self._determine_severity_from_script(script_name, output),
                            'title': f'NSE Detected: {cve_id}',
                            'description': output[:300] + '...' if len(output) > 300 else output,
                            'recommendation': f'Review and patch {cve_id}',
                            'script': script_name,
                            'detection_method': 'nmap_nse_script'
                        }
                        vulnerabilities.append(vuln)
                else:
                    # Generic vulnerability finding
                    vuln = {
                        'id': f'NSE-{script_name.upper()}',
                        'type': 'nse_finding',
                        'source': 'nmap-nse',
                        'severity': self._determine_severity_from_script(script_name, output),
                        'title': f'NSE Finding: {script_name}',
                        'description': output[:300] + '...' if len(output) > 300 else output,
                        'recommendation': f'Review {script_name} findings and apply appropriate security measures',
                        'script': script_name,
                        'detection_method': 'nmap_nse_script'
                    }
                    vulnerabilities.append(vuln)
        except Exception as e:
            print(f"⚠️ Error parsing NSE script {script_name}: {e}")

        return vulnerabilities

    def _parse_service_vulnerability_script(self, script_name: str, output: str, target: str = None,
                                            port: int = None) -> List[Dict[str, Any]]:
        """Parse service-specific vulnerability script output"""
        vulnerabilities = []

        try:
            # Service-specific vulnerability patterns
            if 'http-vuln-' in script_name:
                vulns = self._parse_http_vulnerabilities(script_name, output)
                vulnerabilities.extend(vulns)
            elif 'ssl-' in script_name:
                vulns = self._parse_ssl_vulnerabilities(script_name, output)
                vulnerabilities.extend(vulns)
            elif 'smb-vuln-' in script_name:
                vulns = self._parse_smb_vulnerabilities(script_name, output)
                vulnerabilities.extend(vulns)
        except Exception as e:
            print(f"⚠️ Error parsing service script {script_name}: {e}")

        return vulnerabilities

    # Helper methods for parsing specific vulnerability types
    def _parse_http_vulnerabilities(self, script_name: str, output: str) -> List[Dict[str, Any]]:
        """Parse HTTP-specific vulnerabilities"""
        vulnerabilities = []

        if 'VULNERABLE' in output:
            cve_match = re.search(r'CVE-(\d{4}-\d+)', output)
            cve_id = cve_match.group(0) if cve_match else None

            vuln = {
                'id': cve_id or f'HTTP-{script_name.upper()}',
                'type': 'web_vulnerability',
                'source': 'nmap-nse',
                'severity': 'High' if 'VULNERABLE' in output else 'Medium',
                'title': f'Web Vulnerability: {script_name}',
                'description': output[:300] + '...' if len(output) > 300 else output,
                'recommendation': 'Update web server and apply security patches',
                'script': script_name,
                'category': 'web_application'
            }

            if cve_id:
                vuln['cve_id'] = cve_id

            vulnerabilities.append(vuln)

        return vulnerabilities

    def _parse_ssl_vulnerabilities(self, script_name: str, output: str) -> List[Dict[str, Any]]:
        """Parse SSL/TLS vulnerabilities"""
        vulnerabilities = []

        ssl_severity_map = {
            'ssl-heartbleed': 'Critical',
            'ssl-poodle': 'High',
            'ssl-ccs-injection': 'High',
            'sslv2-drown': 'High',
            'ssl-dh-params': 'Medium'
        }

        if 'VULNERABLE' in output:
            vuln = {
                'id': f'SSL-{script_name.upper()}',
                'type': 'ssl_vulnerability',
                'source': 'nmap-nse',
                'severity': ssl_severity_map.get(script_name, 'Medium'),
                'title': f'SSL/TLS Vulnerability: {script_name}',
                'description': output[:300] + '...' if len(output) > 300 else output,
                'recommendation': self._get_ssl_recommendation(script_name),
                'script': script_name,
                'category': 'ssl_tls'
            }
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _parse_smb_vulnerabilities(self, script_name: str, output: str) -> List[Dict[str, Any]]:
        """Parse SMB vulnerabilities"""
        vulnerabilities = []

        critical_smb_vulns = ['ms17-010', 'ms08-067']

        if 'VULNERABLE' in output:
            severity = 'Critical' if any(crit in script_name for crit in critical_smb_vulns) else 'High'

            vuln = {
                'id': f'SMB-{script_name.upper()}',
                'type': 'smb_vulnerability',
                'source': 'nmap-nse',
                'severity': severity,
                'title': f'SMB Vulnerability: {script_name}',
                'description': output[:300] + '...' if len(output) > 300 else output,
                'recommendation': self._get_smb_recommendation(script_name),
                'script': script_name,
                'category': 'smb'
            }
            vulnerabilities.append(vuln)

        return vulnerabilities

    # Additional helper methods
    def _select_vulnerability_scripts(self, service_type: str) -> List[str]:
        """Select appropriate NSE vulnerability scripts"""
        base_scripts = ['vuln']

        # Add vulners if API key available
        if self.vulners_api_key:
            base_scripts.append('vulners')

        # Service-specific scripts
        service_scripts = {
            'http': ['http-vuln-*', 'ssl-*'],
            'https': ['ssl-*', 'http-vuln-*', 'tls-*'],
            'ssh': ['ssh-*'],
            'ftp': ['ftp-*'],
            'smtp': ['smtp-*'],
            'smb': ['smb-vuln-*'],
            'snmp': ['snmp-*'],
            'mysql': ['mysql-*'],
            'postgresql': ['pgsql-*']
        }

        scripts = base_scripts.copy()

        if service_type and service_type.lower() in service_scripts:
            scripts.extend(service_scripts[service_type.lower()])

        return scripts

    def _enhance_with_vulners_api(self, vulnerabilities: List[Dict[str, Any]],
                                  target: str, port: int, service_type: str) -> List[Dict[str, Any]]:
        """Enhance vulnerabilities with direct Vulners API calls if needed"""
        if not self.vulners_api_key:
            return vulnerabilities

        enhanced = vulnerabilities.copy()

        # If we don't have enough vulnerability data, try direct API call
        if len(vulnerabilities) < 3:
            try:
                print(f"🔍 Enhancing with direct Vulners API call for {target}:{port}")

                # Get additional vulnerability data via API
                api_vulns = self._query_vulners_api_direct(service_type, port)
                enhanced.extend(api_vulns)

            except Exception as e:
                print(f"⚠️ Vulners API enhancement failed: {e}")

        return enhanced

    def _query_vulners_api_direct(self, service_type: str, port: int) -> List[Dict[str, Any]]:
        """Direct query to Vulners API for additional vulnerability data"""
        if not self.vulners_api_key:
            return []

        try:
            api_url = "https://vulners.com/api/v3/search/lucene/"

            # Build search query
            query = f"type:cve AND affectedSoftware.name:{service_type}"

            headers = {
                'Content-Type': 'application/json'
            }

            data = {
                'apikey': self.vulners_api_key,
                'query': query,
                'size': 10
            }

            response = requests.post(api_url, json=data, headers=headers, timeout=10)

            if response.status_code == 200:
                result = response.json()
                return self._parse_vulners_api_response(result)
            else:
                print(f"⚠️ Vulners API returned status {response.status_code}")
                return []

        except Exception as e:
            print(f"❌ Vulners API direct query failed: {e}")
            return []

    def _parse_vulners_api_response(self, api_response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse direct Vulners API response"""
        vulnerabilities = []

        documents = api_response.get('data', {}).get('search', [])

        for doc in documents[:5]:  # Limit to 5 additional vulnerabilities
            doc_data = doc.get('_source', {})

            vuln = {
                'id': doc_data.get('id', 'VULNERS-UNKNOWN'),
                'type': 'cve',
                'source': 'vulners_api_direct',
                'severity': self._cvss_to_severity(doc_data.get('cvss', {}).get('score', 0)),
                'cvss_score': doc_data.get('cvss', {}).get('score', 0),
                'title': doc_data.get('title', 'Vulners API Finding'),
                'description': doc_data.get('description', '')[:300],
                'recommendation': 'Apply security updates and patches',
                'published_date': doc_data.get('published', ''),
                'detection_method': 'vulners_api_direct'
            }
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _extract_exploit_info(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract exploit information from vulnerabilities"""
        exploitable_count = len([v for v in vulnerabilities if v.get('exploit_available')])
        total_exploits = sum([len(v.get('exploit_urls', [])) for v in vulnerabilities])

        return {
            'exploitable_vulnerabilities': exploitable_count,
            'total_exploit_urls': total_exploits,
            'exploit_percentage': round((exploitable_count / len(vulnerabilities)) * 100, 1) if vulnerabilities else 0
        }

    def _assess_risk(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Assess overall risk level"""
        if not vulnerabilities:
            return 'LOW'

        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])
        exploit_count = len([v for v in vulnerabilities if v.get('exploit_available')])

        if critical_count > 0 or exploit_count > 2:
            return 'CRITICAL'
        elif high_count > 2 or exploit_count > 0:
            return 'HIGH'
        elif high_count > 0:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _extract_banner_from_scripts(self, scripts: Dict[str, str]) -> str:
        """Extract banner information from NSE script results"""
        if 'banner' in scripts:
            return scripts['banner']

        # Look for banner info in other scripts
        for script_name, output in scripts.items():
            if 'Server:' in output:
                server_match = re.search(r'Server:\s*([^\r\n]+)', output)
                if server_match:
                    return server_match.group(1).strip()

        return ''

    def _cvss_to_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        elif cvss_score > 0:
            return 'Low'
        else:
            return 'Info'

    def _determine_severity_from_script(self, script_name: str, output: str) -> str:
        """Determine severity based on script name and output"""
        critical_indicators = ['heartbleed', 'ms17-010', 'ms08-067']
        high_indicators = ['poodle', 'beast', 'crime', 'breach']

        script_lower = script_name.lower()
        output_lower = output.lower()

        if any(indicator in script_lower or indicator in output_lower for indicator in critical_indicators):
            return 'Critical'
        elif any(indicator in script_lower or indicator in output_lower for indicator in high_indicators):
            return 'High'
        elif 'vulnerable' in output_lower:
            return 'Medium'
        else:
            return 'Low'

    def _get_ssl_recommendation(self, script_name: str) -> str:
        """Get SSL-specific recommendations"""
        recommendations = {
            'ssl-heartbleed': 'Update OpenSSL to version 1.0.1g or later immediately',
            'ssl-poodle': 'Disable SSLv3 and use TLS 1.2 or later',
            'ssl-ccs-injection': 'Update OpenSSL and disable vulnerable cipher suites',
            'sslv2-drown': 'Disable SSLv2 completely',
            'ssl-dh-params': 'Use stronger Diffie-Hellman parameters (2048-bit or larger)'
        }
        return recommendations.get(script_name, 'Review SSL/TLS configuration and apply security updates')

    def _get_smb_recommendation(self, script_name: str) -> str:
        """Get SMB-specific recommendations"""
        recommendations = {
            'smb-vuln-ms17-010': 'Apply Microsoft Security Bulletin MS17-010 (EternalBlue patch) immediately',
            'smb-vuln-ms08-067': 'Apply Microsoft Security Bulletin MS08-067',
            'smb-vuln-ms06-025': 'Apply Microsoft Security Bulletin MS06-025'
        }
        return recommendations.get(script_name, 'Apply latest Windows security updates')

    def get_available_scripts(self, category: str = 'all') -> List[str]:
        """Get available NSE scripts by category"""
        if category == 'all':
            all_scripts = []
            for scripts in self.nse_scripts.values():
                if isinstance(scripts, list):
                    all_scripts.extend(scripts)
                elif isinstance(scripts, dict):
                    for script_list in scripts.values():
                        all_scripts.extend(script_list)
            return list(set(all_scripts))

        return self.nse_scripts.get(category, [])

    def is_available(self) -> bool:
        """Check if enhanced nmap scanner is available"""
        return self.available

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive scanner status"""
        status = {
            'available': self.available,
            'nmap_binary': False,
            'python_nmap': NMAP_AVAILABLE,
            'vulners_api_key': bool(self.vulners_api_key),
            'nse_scripts': False,
            'error_messages': []
        }

        if not NMAP_AVAILABLE:
            status['error_messages'].append('python-nmap library not installed')

        if self.available:
            try:
                # Check binary
                result = subprocess.run(['nmap', '--version'],
                                        capture_output=True, text=True, timeout=5)
                status['nmap_binary'] = result.returncode == 0

                # Check NSE scripts
                result = subprocess.run(['nmap', '--script-help', 'vuln'],
                                        capture_output=True, text=True, timeout=10)
                status['nse_scripts'] = result.returncode == 0 and 'vuln' in result.stdout

            except Exception as e:
                status['error_messages'].append(f'Status check failed: {str(e)}')

        return status


# Global instance with safe initialization
try:
    enhanced_nmap_scanner = NmapScanner()
    print(f"🎯 Enhanced Nmap Scanner Status: {'✅ Available' if enhanced_nmap_scanner.available else '❌ Unavailable'}")
except Exception as e:
    print(f"❌ Failed to create NmapScanner instance: {e}")
    enhanced_nmap_scanner = None



def passive_discovery(target: str, port_range: str = "1-1000", enable_vulners: bool = True) -> Dict[str, Any]:
    """
    FIXED: Wrapper function for enhanced nmap passive discovery

    Args:
        target: Target IP/domain to scan
        port_range: Port range to scan (e.g., "1-1000")
        enable_vulners: Whether to enable Vulners NSE script

    Returns:
        Dictionary with scan results
    """
    try:
        if not enhanced_nmap_scanner or not enhanced_nmap_scanner.available:
            return {
                'error': 'Enhanced nmap scanner not available',
                'suggestions': [
                    'Install nmap: sudo apt-get install nmap (Linux) or brew install nmap (macOS)',
                    'Install python-nmap: pip install python-nmap',
                    'Check nmap binary is in PATH'
                ]
            }

        # Call the actual nmap discovery function
        result = enhanced_nmap_scanner.passive_port_discovery(
            target=target,
            port_range=port_range,
            enable_vulners=enable_vulners
        )

        return result

    except Exception as e:
        print(f"❌ Passive discovery wrapper error: {e}")
        return {
            'error': f'Passive discovery failed: {str(e)}',
            'suggestions': [
                'Check if nmap is properly installed',
                'Verify target is valid and reachable',
                'Try with a smaller port range',
                'Check network connectivity'
            ]
        }


def enhanced_vulnerability_scan(target: str, port: int, service_type: str = None) -> Dict[str, Any]:
    """
    FIXED: Wrapper function for enhanced vulnerability scanning

    Args:
        target: Target IP to scan
        port: Port number to scan
        service_type: Optional service type hint

    Returns:
        Dictionary with vulnerability scan results
    """
    try:
        if not enhanced_nmap_scanner or not enhanced_nmap_scanner.available:
            return {
                'error': 'Enhanced nmap scanner not available',
                'service_name': 'unknown',
                'vulnerabilities': [],
                'status': 'error'
            }

        # Call the comprehensive vulnerability scan
        result = enhanced_nmap_scanner.comprehensive_vulnerability_scan(
            target=target,
            port=port,
            service_type=service_type
        )

        # Format result for consistency with other scanners
        if 'error' not in result:
            formatted_result = {
                'target': f"{target}:{port}",
                'service_name': result.get('service', 'unknown'),
                'service_info': {
                    'version': result.get('version', ''),
                    'product': result.get('product', ''),
                    'accessible': result.get('state') == 'open'
                },
                'vulnerabilities': result.get('vulnerabilities', []),
                'status': 'completed',
                'scan_method': 'enhanced_nmap_nse',
                'nse_scripts_run': result.get('nse_scripts_run', []),
                'exploit_info': result.get('exploit_info', {}),
                'risk_assessment': result.get('risk_assessment', 'Unknown')
            }
            return formatted_result
        else:
            return result

    except Exception as e:
        print(f"❌ Enhanced vulnerability scan wrapper error: {e}")
        return {
            'error': f'Enhanced vulnerability scan failed: {str(e)}',
            'service_name': 'unknown',
            'vulnerabilities': [],
            'status': 'error'
        }