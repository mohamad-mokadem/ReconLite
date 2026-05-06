import subprocess
from abc import ABC, abstractmethod
from datetime import datetime
import socket
import time
from typing import Dict, Any, List, Optional
from services.vulnerability_integration import VulnerabilityChecker, VulnerabilityIntegration


class BaseScanner(ABC):
    """Enhanced Base class for all port-specific scanners with nmap integration support"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.scan_start_time = None
        self.nmap_scanner = None
        self.cve_integration = None

        # Enhanced nmap integration support
        self.nmap_available = False  # Will be set by scanner manager
        self._nmap_checked = False
        self.nmap_timeout = 30

    @abstractmethod
    def get_supported_ports(self) -> List[int]:
        """Return list of ports this scanner supports"""
        pass

    @abstractmethod
    def get_service_name(self) -> str:
        """Return the service name (e.g., 'FTP', 'SSH')"""
        pass

    @abstractmethod
    def scan(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Main scanning method - must be implemented by each scanner"""
        pass

    def set_nmap_available(self, available: bool):
        """Set nmap availability (called by scanner manager)"""
        self.nmap_available = available
        self._nmap_checked = True
        if available:
            print(f"✅ {self.get_service_name()} scanner: nmap integration enabled")
        else:
            print(f"⚠️ {self.get_service_name()} scanner: using fallback methods (nmap unavailable)")

    def check_nmap_available(self) -> bool:
        """WSL-ONLY nmap check - prevent Windows nmap execution"""
        if self._nmap_checked:
            return self.nmap_available

        try:
            print(f"🐧 {self.get_service_name()} scanner: Checking nmap via WSL only")

            # Only check WSL nmap, never Windows nmap
            result = subprocess.run(['wsl', 'nmap', '--version'],
                                    capture_output=True, text=True, timeout=5)
            self.nmap_available = result.returncode == 0
            self._nmap_checked = True

            if self.nmap_available:
                print(f"✅ {self.get_service_name()} scanner: WSL nmap available")
            else:
                print(f"⚠️ {self.get_service_name()} scanner: WSL nmap not found")

            return self.nmap_available

        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"⚠️ {self.get_service_name()} scanner: WSL not available")
            self.nmap_available = False
            self._nmap_checked = True
            return False
        except Exception as e:
            print(f"⚠️ {self.get_service_name()} scanner: WSL check error: {e}")
            self.nmap_available = False
            self._nmap_checked = True
            return False

    def check_port_connectivity(self, ip: str, port: int) -> Dict[str, Any]:
        """Enhanced port connectivity check with detailed error reporting"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result = sock.connect_ex((ip, port))
            connect_time = (time.time() - start_time) * 1000

            sock.close()

            if result == 0:
                return {
                    'accessible': True,
                    'response_time_ms': round(connect_time, 2),
                    'connection_status': 'success',
                    'port_state': 'open',
                    'connectivity_test': 'passed'
                }
            else:
                return {
                    'accessible': False,
                    'connection_status': 'failed',
                    'error_code': result,
                    'failure_reason': self._get_connection_failure_reason(result),
                    'port_state': 'closed_or_filtered',
                    'connectivity_test': 'failed'
                }
        except socket.timeout:
            return {
                'accessible': False,
                'connection_status': 'timeout',
                'failure_reason': 'Connection timed out - service may not be running or is filtered',
                'port_state': 'filtered_or_timeout',
                'connectivity_test': 'timeout'
            }
        except Exception as e:
            return {
                'accessible': False,
                'connection_status': 'error',
                'error': str(e),
                'failure_reason': f'Network error: {str(e)}',
                'port_state': 'error',
                'connectivity_test': 'error'
            }

    def _get_connection_failure_reason(self, error_code: int) -> str:
        """Get human-readable connection failure reason"""
        error_messages = {
            10060: "Connection timed out - service may not be running or is behind a firewall",
            10061: "Connection refused - port is closed or service not running",
            10064: "Host is down or unreachable",
            10065: "No route to host - network routing issue",
            11001: "Host not found - check IP address",
            11004: "Name resolution failed - DNS issue",
            10013: "Permission denied - insufficient privileges",
            10049: "Cannot assign requested address - invalid address",
            10051: "Network is unreachable",
            10054: "Connection reset by peer - service rejected connection"
        }
        return error_messages.get(error_code, f"Connection failed with error code {error_code}")

    def create_base_result(self, ip: str, port: int) -> Dict[str, Any]:
        """Create enhanced base result structure with nmap support indication"""
        result = {
            'target': f"{ip}:{port}",
            'ip': ip,
            'port': port,
            'service_type': self.get_service_name().lower(),
            'service_name': self.get_service_name(),
            'status': 'scanning',
            'scan_time': datetime.now().isoformat(),
            'scanner_version': '2.1',
            'vulnerabilities': [],
            'recommendations': [],
            'service_info': {},
            'advanced_findings': {},
            'banner': '',
            'steps_completed': [],
            'nmap_enhanced': False,  # Will be set to True if nmap is used successfully
            'nmap_data': {},  # Will contain nmap results if available
            'connectivity_info': {},  # Will contain connectivity test results
            'scan_metadata': {
                'scanner_class': self.__class__.__name__,
                'timeout_used': self.timeout,
                'scan_start_time': datetime.now().isoformat()
            }
        }

        # Add scanner capability information
        result['scanner_capabilities'] = {
            'nmap_available': self.nmap_available,
            'enhanced_detection': self.nmap_available,
            'service_fingerprinting': True,
            'vulnerability_detection': True,
            'banner_grabbing': True,
            'advanced_enumeration': True
        }

        return result

    def create_failed_result(self, ip: str, port: int, failure_reason: str,
                             connectivity_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create enhanced failed scan result with comprehensive failure information"""
        failed_result = {
            'target': f"{ip}:{port}",
            'ip': ip,
            'port': port,
            'service_type': self.get_service_name().lower(),
            'service_name': self.get_service_name(),
            'status': 'failed',
            'scan_time': datetime.now().isoformat(),
            'scanner_version': '2.1',
            'failure_reason': failure_reason,
            'banner': failure_reason,
            'nmap_enhanced': False,
            'nmap_data': {'error': 'Scan failed before nmap execution'},

            # Enhanced failure information for better user experience
            'failure_info': {
                'primary_reason': failure_reason,
                'technical_details': connectivity_info or {},
                'user_suggestions': self._get_failure_suggestions(failure_reason, port),
                'next_steps': self._get_next_steps(port),
                'nmap_attempted': self.nmap_available,
                'fallback_methods_used': True,
                'troubleshooting_guide': self._get_troubleshooting_guide(port)
            },

            # Empty but defined sections to prevent frontend errors
            'vulnerabilities': [],
            'recommendations': self._get_failure_recommendations(failure_reason, port),
            'service_info': {
                'scan_failed': True,
                'accessible': False,
                'nmap_available': self.nmap_available,
                'failure_type': self._classify_failure_type(failure_reason)
            },
            'advanced_findings': {
                'scan_status': 'failed',
                'failure_analysis': {
                    'category': self._classify_failure_type(failure_reason),
                    'severity': self._get_failure_severity(failure_reason),
                    'impact': 'No security assessment possible'
                }
            },
            'steps_completed': ['connectivity'],
            'connectivity_info': connectivity_info or {},
            'scanner_capabilities': {
                'nmap_available': self.nmap_available,
                'enhanced_detection': False,
                'service_fingerprinting': False,
                'vulnerability_detection': False,
                'banner_grabbing': False,
                'advanced_enumeration': False
            },
            'scan_metadata': {
                'scanner_class': self.__class__.__name__,
                'timeout_used': self.timeout,
                'scan_duration': round((time.time() - self.scan_start_time) * 1000, 2) if self.scan_start_time else 0
            }
        }

        if self.scan_start_time:
            failed_result['scan_duration'] = round((time.time() - self.scan_start_time) * 1000, 2)

        return failed_result

    def _classify_failure_type(self, failure_reason: str) -> str:
        """Classify the type of failure for better error handling"""
        failure_reason_lower = failure_reason.lower()

        if 'timeout' in failure_reason_lower:
            return 'timeout'
        elif 'refused' in failure_reason_lower or 'closed' in failure_reason_lower:
            return 'connection_refused'
        elif 'unreachable' in failure_reason_lower:
            return 'network_unreachable'
        elif 'permission' in failure_reason_lower or 'denied' in failure_reason_lower:
            return 'permission_denied'
        elif 'not found' in failure_reason_lower or 'invalid' in failure_reason_lower:
            return 'invalid_target'
        else:
            return 'unknown'

    def _get_failure_severity(self, failure_reason: str) -> str:
        """Get failure severity for impact assessment"""
        failure_type = self._classify_failure_type(failure_reason)

        severity_map = {
            'timeout': 'medium',
            'connection_refused': 'low',
            'network_unreachable': 'high',
            'permission_denied': 'medium',
            'invalid_target': 'high',
            'unknown': 'medium'
        }

        return severity_map.get(failure_type, 'medium')

    def _get_failure_suggestions(self, failure_reason: str, port: int) -> List[str]:
        """Get enhanced failure suggestions based on failure type and service"""
        suggestions = []
        failure_type = self._classify_failure_type(failure_reason)
        service_name = self.get_service_name()

        if failure_type == 'connection_refused':
            suggestions.extend([
                f"Verify that {service_name} service is running on the target system",
                f"Check if port {port} is the correct port for {service_name} service",
                "Ensure no firewall is blocking the connection",
                "Confirm you have permission to scan this target",
                f"Try alternative {service_name} ports if service uses non-standard ports"
            ])

            # Add service-specific alternative ports
            alt_ports = self._get_alternative_ports(port)
            if alt_ports:
                suggestions.append(f"Consider trying alternative ports: {', '.join(map(str, alt_ports))}")

        elif failure_type == 'timeout':
            suggestions.extend([
                "Target may be behind a firewall that drops packets",
                "Network connection may be slow or congested",
                "Target system may be overloaded or unresponsive",
                "Try increasing the scan timeout value",
                "Try scanning from a different network location",
                "Consider using TCP connect scan instead of SYN scan"
            ])

        elif failure_type == 'network_unreachable':
            suggestions.extend([
                "Verify the target IP address is correct and reachable",
                "Check your network connection and routing",
                "Target may be on a different network segment",
                "VPN or network routing configuration may need adjustment",
                "Try pinging the target first to verify basic connectivity"
            ])

        elif failure_type == 'permission_denied':
            suggestions.extend([
                "Run the scan with appropriate privileges (may need administrator/root)",
                "Check if security software is blocking the scan",
                "Verify network permissions and access policies",
                "Consider using alternative scanning methods"
            ])

        else:
            suggestions.extend([
                "Double-check the target IP address and port number",
                "Verify network connectivity to the target",
                "Ensure you have permission to scan this target",
                "Try scanning a known working target to test your setup",
                "Check if the service is actually running on the target"
            ])

        # Add nmap-specific suggestions if available
        if self.nmap_available:
            suggestions.append(f"Try nmap direct scan: nmap -sV -p {port} <target>")
        else:
            suggestions.append("Consider installing nmap for enhanced detection capabilities")

        return suggestions

    def _get_alternative_ports(self, port: int) -> List[int]:
        """Get alternative ports for common services"""
        port_alternatives = {
            21: [990, 2121, 8021],  # FTP alternatives
            22: [2222, 22000, 2200],  # SSH alternatives
            23: [2323, 992],  # Telnet alternatives
            25: [587, 465, 2525],  # SMTP alternatives
            53: [5353, 853],  # DNS alternatives
            80: [8080, 8000, 8888, 8008],  # HTTP alternatives
            110: [995],  # POP3 alternatives
            143: [993],  # IMAP alternatives
            443: [8443, 8080, 9443],  # HTTPS alternatives
            445: [139, 135],  # SMB alternatives
            993: [143],  # IMAPS alternatives
            995: [110]  # POP3S alternatives
        }
        return port_alternatives.get(port, [])

    def _get_next_steps(self, port: int) -> List[str]:
        """Get next steps based on service type and failure"""
        service_name = self.get_service_name()

        service_specific_steps = {
            'FTP': [
                f"Test FTP connectivity: ftp <target>",
                f"Try telnet to port {port}: telnet <target> {port}",
                "Check for FTPS on port 990",
                "Verify FTP service is actually running",
                "Check FTP server logs for connection attempts"
            ],
            'SSH': [
                f"Test SSH connectivity: ssh user@<target> -p {port}",
                f"Try telnet to port {port}: telnet <target> {port}",
                "Check common SSH ports: 22, 2222, 22000",
                "Verify SSH service status on target system",
                "Check SSH server configuration"
            ],
            'HTTP': [
                f"Test web connectivity: curl http://<target>:{port}",
                f"Try browser access: http://<target>:{port}",
                "Check if HTTPS is used instead: port 443",
                "Verify web server is running",
                "Check for web service on alternative ports"
            ],
            'HTTPS': [
                f"Test HTTPS connectivity: curl https://<target>:{port}",
                f"Try browser access: https://<target>:{port}",
                "Check certificate validity and trust",
                "Try HTTP port 80 instead",
                "Verify SSL/TLS service configuration"
            ],
            'SMTP': [
                f"Test SMTP connectivity: telnet <target> {port}",
                "Check alternative SMTP ports: 587, 465, 2525",
                "Verify mail server is running",
                "Check SMTP server authentication requirements",
                "Test with mail client configuration"
            ],
            'SMB': [
                f"Test SMB connectivity: smbclient -L <target>",
                "Check NetBIOS port: 139",
                "Verify SMB/CIFS service is enabled",
                "Check Windows file sharing settings",
                "Test with network file manager"
            ]
        }

        steps = service_specific_steps.get(service_name, [
            f"Use nmap to verify port status: nmap -p {port} <target>",
            "Check target system documentation for correct ports",
            "Verify service is actually running on target system",
            "Test connectivity with service-specific tools"
        ])

        # Add general troubleshooting steps
        steps.extend([
            "Verify basic network connectivity with ping",
            "Check for firewall rules blocking the connection",
            "Confirm target system is powered on and accessible"
        ])

        return steps

    def _get_troubleshooting_guide(self, port: int) -> Dict[str, Any]:
        """Get comprehensive troubleshooting guide"""
        return {
            'basic_tests': [
                f"ping <target>",
                f"telnet <target> {port}",
                f"nmap -p {port} <target>"
            ],
            'common_issues': [
                'Firewall blocking connection',
                'Service not running',
                'Wrong port number',
                'Network connectivity issues',
                'Permission restrictions'
            ],
            'diagnostic_commands': [
                f"nmap -sV -p {port} <target>",
                f"nc -zv <target> {port}",
                f"ncat <target> {port}"
            ],
            'service_specific_tests': self._get_service_specific_tests(port)
        }

    def _get_service_specific_tests(self, port: int) -> List[str]:
        """Get service-specific diagnostic tests"""
        service_name = self.get_service_name()

        service_tests = {
            'FTP': ['ftp <target>', 'curl ftp://<target>'],
            'SSH': ['ssh -p 22 user@<target>', 'ssh-keyscan <target>'],
            'HTTP': ['curl http://<target>', 'wget http://<target>'],
            'HTTPS': ['curl https://<target>', 'openssl s_client -connect <target>:443'],
            'SMTP': ['telnet <target> 25', 'swaks --to test@example.com --server <target>'],
            'SMB': ['smbclient -L <target>', 'nmblookup <target>']
        }

        return service_tests.get(service_name, [f'telnet <target> {port}'])

    def _get_failure_recommendations(self, failure_reason: str, port: int) -> List[str]:
        """Get recommendations specific to the failure type"""
        failure_type = self._classify_failure_type(failure_reason)

        recommendations = {
            'timeout': [
                'Increase scan timeout values',
                'Use TCP connect scan instead of SYN scan',
                'Check for rate limiting or IDS interference'
            ],
            'connection_refused': [
                'Verify service is running and properly configured',
                'Check service binding configuration (localhost vs all interfaces)',
                'Review service access controls and allowed connections'
            ],
            'network_unreachable': [
                'Verify network routing and connectivity',
                'Check VPN or tunnel configurations',
                'Confirm target is on an accessible network segment'
            ],
            'permission_denied': [
                'Run scan with appropriate administrative privileges',
                'Review local firewall and security software settings',
                'Check network access policies and restrictions'
            ]
        }

        return recommendations.get(failure_type, [
            'Review target configuration and accessibility',
            'Verify scan parameters and target information',
            'Test with known working targets first'
        ])

    def enhance_with_nmap_if_available(self, results: Dict[str, Any], ip: str, port: int) -> Dict[str, Any]:
        """Helper method for scanners to use nmap if available"""
        if not self.check_nmap_available():
            results['nmap_data'] = {'error': 'Nmap not available on this system'}
            results['nmap_enhanced'] = False
            return results

        try:
            # This should be implemented by individual scanners that support nmap
            if hasattr(self, '_run_nmap_scan'):
                print(f"🎯 Running nmap scan for {self.get_service_name()} service...")
                nmap_results = self._run_nmap_scan(ip, port)
                results['nmap_data'] = nmap_results

                if not nmap_results.get('error'):
                    results['nmap_enhanced'] = True
                    print(f"✅ Nmap scan successful for {self.get_service_name()}")

                    # Merge nmap service info if available
                    if nmap_results.get('service_info'):
                        results['service_info'].update(nmap_results['service_info'])

                    # Update banner if nmap provides better information
                    if nmap_results.get('banner') and not results.get('banner'):
                        results['banner'] = nmap_results['banner']

                    # Add nmap metadata
                    results['scan_metadata']['nmap_integration'] = True
                    results['scan_metadata']['nmap_scripts_used'] = len(nmap_results.get('scripts', {}))
                else:
                    print(f"⚠️ Nmap scan failed for {self.get_service_name()}: {nmap_results['error']}")
                    results['nmap_enhanced'] = False
            else:
                results['nmap_data'] = {
                    'error': f'Nmap integration not implemented for {self.get_service_name()} scanner'}
                results['nmap_enhanced'] = False

        except Exception as e:
            print(f"❌ Nmap integration error for {self.get_service_name()}: {e}")
            results['nmap_data'] = {'error': f'Nmap integration failed: {str(e)}'}
            results['nmap_enhanced'] = False

        return results

    def add_vulnerability(self, results: Dict[str, Any], vuln_id: str,
                          severity: str, title: str, description: str,
                          recommendation: str, **kwargs):
        """Enhanced helper to add vulnerability to results"""
        if 'vulnerabilities' not in results:
            results['vulnerabilities'] = []

        vulnerability = {
            'id': vuln_id,
            'severity': severity,
            'title': title,
            'description': description,
            'recommendation': recommendation,
            'source': f'{self.get_service_name()}_scanner',
            'detection_time': datetime.now().isoformat()
        }

        # Add optional fields
        for key, value in kwargs.items():
            vulnerability[key] = value

        results['vulnerabilities'].append(vulnerability)

    def add_recommendation(self, results: Dict[str, Any], recommendation: str, category: str = 'general'):
        """Enhanced helper to add recommendation to results"""
        if 'recommendations' not in results:
            results['recommendations'] = []

        # Avoid duplicates
        if recommendation not in results['recommendations']:
            results['recommendations'].append(recommendation)

        # Track recommendation metadata
        if 'scan_metadata' not in results:
            results['scan_metadata'] = {}
        if 'recommendations_by_category' not in results['scan_metadata']:
            results['scan_metadata']['recommendations_by_category'] = {}
        if category not in results['scan_metadata']['recommendations_by_category']:
            results['scan_metadata']['recommendations_by_category'][category] = []

        results['scan_metadata']['recommendations_by_category'][category].append(recommendation)

    def mark_step_completed(self, results: Dict[str, Any], step: str):
        """Enhanced helper to mark a scanning step as completed"""
        if 'steps_completed' not in results:
            results['steps_completed'] = []

        if step not in results['steps_completed']:
            results['steps_completed'].append(step)

        # Add step completion metadata
        if 'scan_metadata' not in results:
            results['scan_metadata'] = {}
        if 'step_timestamps' not in results['scan_metadata']:
            results['scan_metadata']['step_timestamps'] = {}

        results['scan_metadata']['step_timestamps'][step] = datetime.now().isoformat()

    def update_service_info(self, results: Dict[str, Any], info: Dict[str, Any]):
        """Enhanced helper to update service info"""
        if 'service_info' not in results:
            results['service_info'] = {}

        results['service_info'].update(info)

        # Track service info sources
        if 'scan_metadata' not in results:
            results['scan_metadata'] = {}
        if 'service_info_sources' not in results['scan_metadata']:
            results['scan_metadata']['service_info_sources'] = []

        source = f'{self.get_service_name()}_scanner'
        if source not in results['scan_metadata']['service_info_sources']:
            results['scan_metadata']['service_info_sources'].append(source)

    def finalize_results(self, results: Dict[str, Any], success: bool = True) -> Dict[str, Any]:
        """Enhanced finalize with comprehensive metadata"""
        results['status'] = 'completed' if success else 'failed'

        if self.scan_start_time:
            scan_duration = round((time.time() - self.scan_start_time) * 1000, 2)
            results['scan_duration'] = scan_duration

            # Add performance metadata
            if 'scan_metadata' not in results:
                results['scan_metadata'] = {}

            results['scan_metadata'].update({
                'scan_end_time': datetime.now().isoformat(),
                'total_scan_duration_ms': scan_duration,
                'performance_category': self._categorize_scan_performance(scan_duration)
            })

        # Add final scanner capabilities and status
        if 'nmap_data' in results:
            nmap_success = not results['nmap_data'].get('error')
            results['scanner_capabilities']['enhanced_detection'] = nmap_success
            results['scanner_capabilities']['nmap_integration_successful'] = nmap_success

        # Add scan summary
        results['scan_summary'] = {
            'scanner_used': self.get_service_name(),
            'scan_successful': success,
            'steps_completed': len(results.get('steps_completed', [])),
            'vulnerabilities_found': len(results.get('vulnerabilities', [])),
            'recommendations_provided': len(results.get('recommendations', [])),
            'nmap_enhanced': results.get('nmap_enhanced', False),
            'enhanced_features_used': self._count_enhanced_features(results)
        }

        return results

    def _categorize_scan_performance(self, duration_ms: float) -> str:
        """Categorize scan performance based on duration"""
        if duration_ms < 1000:
            return 'very_fast'
        elif duration_ms < 5000:
            return 'fast'
        elif duration_ms < 15000:
            return 'normal'
        elif duration_ms < 30000:
            return 'slow'
        else:
            return 'very_slow'

    def _count_enhanced_features(self, results: Dict[str, Any]) -> int:
        """Count number of enhanced features used in scan"""
        features = 0

        if results.get('nmap_enhanced'):
            features += 1
        if results.get('vulnerabilities'):
            features += 1
        if results.get('advanced_findings'):
            features += 1
        if results.get('service_info'):
            features += 1

        return features

    def enable_cve_checking(self, nvd_api_key: str = None):
        """Enable CVE vulnerability checking"""
        try:
            self.cve_integration = VulnerabilityIntegration(nvd_api_key=nvd_api_key, enabled=True)
            print(f"✅ {self.get_service_name()} scanner: CVE checking enabled")
        except Exception as e:
            print(f"⚠️ {self.get_service_name()} scanner: CVE checking failed to initialize: {e}")
            self.cve_integration = None

    def enhance_results_with_cve(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced CVE results integration"""
        if not self.cve_integration:
            return results

        try:
            enhanced_results = self.cve_integration.enhance_scan_results(results)

            # Add CVE integration metadata
            if 'scan_metadata' not in enhanced_results:
                enhanced_results['scan_metadata'] = {}

            enhanced_results['scan_metadata']['cve_integration'] = True
            enhanced_results['scan_metadata']['cve_vulnerabilities_found'] = len(
                enhanced_results.get('cve_vulnerabilities', [])
            )

            return enhanced_results
        except Exception as e:
            print(f"⚠️ {self.get_service_name()} scanner: CVE enhancement failed: {e}")
            return results

    def get_scanner_status(self) -> Dict[str, Any]:
        """Get comprehensive scanner status and capabilities"""
        return {
            'scanner_name': self.get_service_name(),
            'scanner_class': self.__class__.__name__,
            'supported_ports': self.get_supported_ports(),
            'capabilities': {
                'nmap_integration': self.nmap_available,
                'cve_checking': self.cve_integration is not None,
                'vulnerability_detection': True,
                'service_fingerprinting': True,
                'banner_grabbing': True,
                'advanced_enumeration': True
            },
            'configuration': {
                'timeout': self.timeout,
                'nmap_timeout': self.nmap_timeout
            },
            'status': 'ready'
        }