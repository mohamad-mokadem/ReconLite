# Enhanced scanner_manager.py with SMB scanner integration
import time
from typing import Dict, Any, List, Optional
from datetime import datetime


from services.ftp_scanner import FTPScanner
from services.https_scanner import HTTPSScanner
from services.smb_scanner import SMBScanner  # Add SMB Scanner import
from services.smtp_scanner import SMTPScanner
from services.snmp_scanner import SNMPScanner
from services.ssh_scanner import SSHScanner
from .shodan_integration import ShodanIntegration


class ScannerManager:
    """Enhanced Scanner Manager with SMB scanner integration"""

    def __init__(self):
        # Fix 1: Initialize nmap availability check BEFORE scanner initialization
        self.nmap_available = self._check_nmap_availability()

        # Fix 2: Initialize scanners with nmap capability info
        self.scanners = self._initialize_scanners()

        # Keep existing integrations
        self.shodan_integration = None
        self.vulnerability_checker = None

        # Fix 3: Enhanced nmap should be separate from individual scanner nmap usage
        try:
            from .nmap_scanner import enhanced_nmap_scanner
            self.enhanced_nmap = enhanced_nmap_scanner if self._check_enhanced_nmap_available() else None
            self.ENHANCED_NMAP_AVAILABLE = self.enhanced_nmap is not None
        except ImportError:
            self.enhanced_nmap = None
            self.ENHANCED_NMAP_AVAILABLE = False

    def _check_nmap_availability(self) -> bool:
        """Check if nmap is available system-wide for individual scanners"""
        try:
            import subprocess
            result = subprocess.run(['nmap', '--version'],
                                    capture_output=True, text=True, timeout=5)
            available = result.returncode == 0
            if available:
                print("✅ Nmap available for individual scanner use")
            else:
                print("⚠️ Nmap not available - scanners will use fallback methods")
            return available
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("⚠️ Nmap not found in PATH - scanners will use fallback methods")
            return False
        except Exception as e:
            print(f"⚠️ Error checking nmap availability: {e}")
            return False

    def _initialize_scanners(self) -> Dict[int, Any]:
        """Initialize all available scanners with nmap capability info"""
        scanners = {}

        # FTP Scanner - Pass nmap availability info
        ftp_scanner = FTPScanner()
        # Fix 4: Set nmap availability on the scanner
        if hasattr(ftp_scanner, 'set_nmap_available'):
            ftp_scanner.set_nmap_available(self.nmap_available)

        for port in ftp_scanner.get_supported_ports():
            scanners[port] = ftp_scanner

        # SSH Scanner
        ssh_scanner = SSHScanner()
        if hasattr(ssh_scanner, 'set_nmap_available'):
            ssh_scanner.set_nmap_available(self.nmap_available)
        for port in ssh_scanner.get_supported_ports():
            scanners[port] = ssh_scanner

        # HTTP Scanner
        http_scanner = HTTPSScanner()
        if hasattr(http_scanner, 'set_nmap_available'):
            http_scanner.set_nmap_available(self.nmap_available)
        for port in http_scanner.get_supported_ports():
            scanners[port] = http_scanner

        # SMTP Scanner
        smtp_scanner = SMTPScanner()
        if hasattr(smtp_scanner, 'set_nmap_available'):
            smtp_scanner.set_nmap_available(self.nmap_available)
        for port in smtp_scanner.get_supported_ports():
            scanners[port] = smtp_scanner

        https_scanner = HTTPSScanner()
        if hasattr(https_scanner, 'set_nmap_available'):
            https_scanner.set_nmap_available(self.nmap_available)
        for port in https_scanner.get_supported_ports():
            scanners[port] = https_scanner

        # SMB Scanner - NEW ADDITION
        smb_scanner = SMBScanner()
        if hasattr(smb_scanner, 'set_nmap_available'):
            smb_scanner.set_nmap_available(self.nmap_available)
        for port in smb_scanner.get_supported_ports():
            scanners[port] = smb_scanner

        # SNMP Scanner
        snmp_scanner = SNMPScanner()
        if hasattr(snmp_scanner, 'set_nmap_available'):
            snmp_scanner.set_nmap_available(self.nmap_available)
        for port in snmp_scanner.get_supported_ports():
            scanners[port] = snmp_scanner

        print(f"✅ Scanner Manager: Initialized {len(set(scanners.values()))} scanners for {len(scanners)} ports")
        print(f"🎯 Nmap Support: {'Available' if self.nmap_available else 'Unavailable'} for individual scanners")
        print(f"🏢 SMB Scanner: Added for ports {smb_scanner.get_supported_ports()}")

        return scanners

    def _check_enhanced_nmap_available(self) -> bool:
        """Check if enhanced nmap integration is available (separate from individual scanner nmap)"""
        try:
            from .nmap_scanner import enhanced_nmap_scanner
            return hasattr(enhanced_nmap_scanner, 'is_available') and enhanced_nmap_scanner.is_available()
        except:
            return False

    def scan_service(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Enhanced scan_service with SMB scanner support"""
        try:

            use_enhanced_nmap = kwargs.get('use_enhanced_nmap', False)

            if use_enhanced_nmap and self.ENHANCED_NMAP_AVAILABLE and self.enhanced_nmap is not None:
                if hasattr(self.enhanced_nmap, 'is_available') and self.enhanced_nmap.is_available():
                    print(f"🎯 Using enhanced nmap scan for {ip}:{port}")
                    return self.enhanced_vulnerability_scan_with_nmap(ip, port, kwargs.get('service_type'))

            # Standard scanning logic with individual scanner nmap support
            if port not in self.scanners:
                return {
                    'target': f"{ip}:{port}",
                    'status': 'unsupported',
                    'error': f'No scanner available for port {port}',
                    'supported_ports': self.get_supported_ports()
                }

            scanner = self.scanners[port]
            service_name = scanner.get_service_name()

            print(f"🔍 Scanning {ip}:{port} using {service_name} scanner")

            # Fix 6: Pass nmap availability to scanner if it supports it
            if hasattr(scanner, 'nmap_available'):
                scanner.nmap_available = self.nmap_available

            # Extract integration options from kwargs
            enable_shodan = kwargs.get('enable_shodan', False)
            enable_vuln_check = False
            use_pre_scan = kwargs.get('use_pre_scan', False)

            # Step 1: Pre-scan intelligence (if enabled)
            pre_scan_intel = None
            if enable_shodan and self.shodan_integration and use_pre_scan:
                print("🔍 Getting pre-scan intelligence from Shodan...")
                pre_scan_intel = self.shodan_integration.get_pre_scan_intelligence(ip, 'ip')

            # Step 2: Perform the actual scan
            scan_start_time = time.time()
            results = scanner.scan(ip, port, **kwargs)
            scan_duration = round((time.time() - scan_start_time) * 1000, 2)

            # Fix 7: Better handling of scanner results with nmap data
            if 'nmap_data' in results and not results['nmap_data'].get('error'):
                print(f"✅ {service_name} scanner used nmap successfully")
                results['nmap_enhanced'] = True
            elif 'nmap_data' in results and results['nmap_data'].get('error'):
                print(f"⚠️ {service_name} scanner nmap unavailable: {results['nmap_data']['error']}")
                results['nmap_enhanced'] = False
            else:
                results['nmap_enhanced'] = False

            # Step 2: Add integration metadata
            results['integrations_used'] = {
                'shodan': enable_shodan and self.shodan_integration is not None,
                'enhanced_vulnerability_checking': enable_vuln_check and self.vulnerability_checker is not None,
                'individual_scanner_nmap': results.get('nmap_enhanced', False),
                'enhanced_nmap': False,  # This path doesn't use enhanced nmap
                'pre_scan_intelligence': pre_scan_intel is not None,
                'vulnerability_sources': []
            }

            # Track which vulnerability sources were used
            if enable_vuln_check and self.vulnerability_checker:
                if results.get('vulnerability_summary', {}).get('detection_sources'):
                    results['integrations_used']['vulnerability_sources'] = results['vulnerability_summary'][
                        'detection_sources']

            if pre_scan_intel:
                results['pre_scan_intelligence'] = pre_scan_intel

            results['enhanced_scan_duration'] = scan_duration

            print(f"✅ Enhanced {service_name} scan completed for {ip}:{port}")
            return results

        except Exception as e:
            print(f"❌ Enhanced scan failed for {ip}:{port}: {e}")
            return {
                'target': f"{ip}:{port}",
                'status': 'error',
                'error': str(e),
                'scanner_type': scanner.get_service_name() if 'scanner' in locals() else 'unknown'
            }

    def scan_service_aggressive(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Aggressive scanning with enhanced NSE scripts"""
        try:
            if port not in self.scanners:
                return {
                    'target': f"{ip}:{port}",
                    'status': 'unsupported',
                    'error': f'No scanner available for port {port}'
                }

            scanner = self.scanners[port]
            service_name = scanner.get_service_name()

            # Check if scanner supports aggressive mode
            if hasattr(scanner, 'scan_aggressive'):
                print(f"🎯 Running aggressive {service_name} scan for {ip}:{port}")

                scan_start_time = time.time()
                results = scanner.scan_aggressive(ip, port, **kwargs)
                scan_duration = round((time.time() - scan_start_time) * 1000, 2)

                # Add aggressive scan metadata
                results['aggressive_scan'] = True
                results['aggressive_scan_duration'] = scan_duration

                return results
            else:
                return {
                    'target': f"{ip}:{port}",
                    'status': 'not_supported',
                    'error': f'Aggressive scanning not supported for {service_name}'
                }

        except Exception as e:
            return {
                'target': f"{ip}:{port}",
                'status': 'error',
                'error': f'Aggressive scan failed: {str(e)}'
            }

    def get_supported_ports(self) -> List[int]:
        """Get list of all supported ports"""
        return list(self.scanners.keys())

    def get_scanner_info(self) -> Dict[str, List[int]]:
        """Get scanner information grouped by service type"""
        scanner_info = {}

        for port, scanner in self.scanners.items():
            service_name = scanner.get_service_name()
            if service_name not in scanner_info:
                scanner_info[service_name] = []
            scanner_info[service_name].append(port)

        return scanner_info

    def get_pre_scan_intelligence(self, target: str, target_type: str) -> Dict[str, Any]:
        """Get pre-scan intelligence from Shodan and other sources"""
        if not self.shodan_integration:
            return {'error': 'Shodan integration not available'}

        try:
            return self.shodan_integration.get_pre_scan_intelligence(target, target_type)
        except Exception as e:
            return {'error': f'Pre-scan intelligence failed: {str(e)}'}

    def generate_scan_plan(self, target: str, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate optimized scan plan based on intelligence"""
        if not self.shodan_integration:
            return {'error': 'Shodan integration not available'}

        try:
            return self.shodan_integration.generate_scan_plan(target, intelligence_data)
        except Exception as e:
            return {'error': f'Scan plan generation failed: {str(e)}'}

    def get_integration_status(self) -> Dict[str, Any]:
        """Enhanced integration status including individual scanner nmap support"""
        status = {
            'scanner_manager': {
                'enabled': True,
                'scanners_loaded': len(set(self.scanners.values())),
                'ports_supported': len(self.scanners),
                'nmap_support': self.nmap_available,
                'status': 'healthy'
            },
            'integrations': {
                'shodan_intelligence': {
                    'enabled': self.shodan_integration is not None,
                    'available': self.shodan_integration.is_available() if self.shodan_integration else False,
                    'status': 'healthy' if self.shodan_integration and self.shodan_integration.is_available() else 'disabled'
                },
                'enhanced_vulnerability_checking': {
                    'enabled': self.vulnerability_checker is not None,
                    'status': 'healthy' if self.vulnerability_checker else 'disabled',
                    'sources': []
                },
                'individual_scanner_nmap': {  # NEW
                    'enabled': self.nmap_available,
                    'status': 'healthy' if self.nmap_available else 'unavailable',
                    'features': [
                        'FTP service fingerprinting',
                        'SMB vulnerability detection',
                        'NSE script integration per scanner',
                        'Enhanced banner detection',
                        'Service version detection'
                    ] if self.nmap_available else []
                },
                'enhanced_nmap': {
                    'enabled': self.ENHANCED_NMAP_AVAILABLE,
                    'status': 'healthy' if self.ENHANCED_NMAP_AVAILABLE else 'unavailable',
                    'features': [
                        'Comprehensive vulnerability scanning',
                        'Vulners API integration',
                        'Passive port discovery',
                        'Advanced NSE script suite'
                    ] if self.ENHANCED_NMAP_AVAILABLE else []
                }
            },
            'capabilities': [
                'Multi-protocol service scanning',
                'Enhanced banner analysis and fingerprinting'
            ]
        }

        # Add capabilities based on nmap availability
        if self.nmap_available:
            status['capabilities'].extend([
                'Individual scanner nmap integration',
                'Enhanced service fingerprinting',
                'NSE script support per service',
                'SMB vulnerability scanning with WSL integration'
            ])

        # Rest of the existing capabilities logic...
        if self.shodan_integration and self.shodan_integration.is_available():
            status['capabilities'].extend([
                'Pre-scan intelligence gathering',
                'Historical service data analysis',
                'Scan optimization and prioritization'
            ])

        if self.vulnerability_checker:
            vuln_status = self.vulnerability_checker.get_integration_status()
            status['integrations']['enhanced_vulnerability_checking'].update({
                'vulners_api_enabled': vuln_status['vulners_api']['enabled'],
                'searchsploit_available': vuln_status['searchsploit']['available'],
                'sources': [
                    'Vulners API' if vuln_status['vulners_api']['enabled'] else None,
                    'Searchsploit' if vuln_status['searchsploit']['available'] else None
                ],
                'capabilities': vuln_status['capabilities']
            })

            # Remove None values from sources
            status['integrations']['enhanced_vulnerability_checking']['sources'] = [
                s for s in status['integrations']['enhanced_vulnerability_checking']['sources'] if s
            ]

        return status

    def initialize_integrations(self, shodan_api_key: str = None, vulners_api_key: str = None):
        """Initialize integrations with API keys"""
        try:
            if shodan_api_key:
                from .shodan_integration import ShodanIntegration
                self.shodan_integration = ShodanIntegration(shodan_api_key)
                print("✅ Shodan integration initialized")

            if vulners_api_key:
                from .vulnerability_integration import VulnerabilityChecker
                self.vulnerability_checker = VulnerabilityChecker(vulners_api_key)
                print("✅ Vulnerability checker initialized")

        except Exception as e:
            print(f"⚠️ Integration initialization error: {e}")

    def enhanced_scan_service(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Enhanced scanning service with all integrations"""
        return self.scan_service(ip, port, **kwargs)

    def bulk_scan_with_intelligence(self, targets: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Bulk scan multiple targets with intelligence optimization"""
        results = []

        for target_info in targets:
            ip = target_info.get('ip')
            port = target_info.get('port')

            if ip and port:
                result = self.enhanced_scan_service(ip, port, **kwargs)
                results.append(result)
            else:
                results.append({
                    'error': 'Invalid target format',
                    'target_info': target_info
                })

        return results

    def quick_intelligence_lookup(self, target: str, target_type: str = 'ip') -> Dict[str, Any]:
        """Quick intelligence lookup for a target"""
        return self.get_pre_scan_intelligence(target, target_type)

    def get_enhanced_capabilities(self) -> Dict[str, Any]:
        """Get enhanced capabilities information"""
        return {
            'enhanced_features': {
                'shodan_intelligence': {
                    'enabled': self.shodan_integration is not None,
                    'description': 'Pre-scan intelligence and historical data'
                },
                'cve_detection': {
                    'enabled': self.vulnerability_checker is not None,
                    'description': 'CVE vulnerability detection and analysis'
                },
                'advanced_scanning': {
                    'enabled': self.nmap_available,
                    'description': 'Advanced nmap integration for enhanced detection'
                }
            },
            'scanner_features': {
                'individual_nmap_integration': {
                    'enabled': self.nmap_available,
                    'description': 'Individual scanner nmap integration'
                },
                'enhanced_nmap': {
                    'enabled': self.ENHANCED_NMAP_AVAILABLE,
                    'description': 'Comprehensive nmap vulnerability scanning'
                },
                'smb_advanced_scanning': {
                    'enabled': self._check_smb_wsl_tools(),
                    'description': 'Advanced SMB scanning with WSL tools'
                }
            },
            'supported_services': list(self.get_scanner_info().keys()),
            'total_ports_supported': len(self.get_supported_ports())
        }

    def _check_smb_wsl_tools(self) -> bool:
        """Check if SMB WSL tools are available"""
        try:
            import subprocess
            # Test basic WSL functionality
            result = subprocess.run(['wsl', 'echo', 'test'],
                                    capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def validate_scan_target(self, target: str, target_type: str = 'ip') -> Dict[str, Any]:
        """Validate scan target"""
        validation = {
            'valid': False,
            'target': target,
            'target_type': target_type,
            'issues': [],
            'recommendations': []
        }

        if target_type == 'ip':
            try:
                import ipaddress
                ipaddress.ip_address(target)
                validation['valid'] = True
                validation['recommendations'].append('Target IP format is valid')
            except ValueError:
                validation['issues'].append('Invalid IP address format')
                validation['recommendations'].append('Please provide a valid IPv4 or IPv6 address')

        elif target_type == 'domain':
            import re
            domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,'
            if re.match(domain_pattern, target):
                validation['valid'] = True
                validation['recommendations'].append('Domain format is valid')
            else:
                validation['issues'].append('Invalid domain format')
                validation['recommendations'].append('Please provide a valid domain name')

        return validation

    def check_service_health(self) -> Dict[str, Any]:
        """Check service health"""
        return {
            'scanner_manager': 'healthy',
            'scanners_loaded': len(set(self.scanners.values())),
            'integrations': {
                'shodan': 'healthy' if self.shodan_integration else 'disabled',
                'vulnerability_checker': 'healthy' if self.vulnerability_checker else 'disabled',
                'nmap': 'available' if self.nmap_available else 'unavailable',
                'smb_wsl_tools': 'available' if self._check_smb_wsl_tools() else 'unavailable'
            },
            'nmap_available': self.nmap_available,
            'enhanced_nmap_available': self.ENHANCED_NMAP_AVAILABLE,
            'smb_scanner_ready': 139 in self.scanners and 445 in self.scanners
        }

    def enhanced_vulnerability_scan_with_nmap(self, ip: str, port: int, service_type: str = None) -> Dict[str, Any]:
        """Enhanced vulnerability scan using nmap"""
        if not self.ENHANCED_NMAP_AVAILABLE:
            return {'error': 'Enhanced nmap not available'}

        try:
            return self.enhanced_nmap.comprehensive_vulnerability_scan(ip, port, service_type)
        except Exception as e:
            return {'error': f'Enhanced nmap scan failed: {str(e)}'}

    def passive_discovery(self, target: str, port_range: str = '1-1000') -> Dict[str, Any]:
        """Passive port discovery using nmap"""
        if not self.ENHANCED_NMAP_AVAILABLE:
            return {'error': 'Enhanced nmap not available for passive discovery'}

        try:
            return self.enhanced_nmap.passive_port_discovery(target, port_range)
        except Exception as e:
            return {'error': f'Passive discovery failed: {str(e)}'}

    def get_smb_scanner_status(self) -> Dict[str, Any]:
        """Get SMB scanner specific status"""
        smb_ports = [139, 445]
        smb_available = all(port in self.scanners for port in smb_ports)

        status = {
            'smb_scanner_available': smb_available,
            'smb_ports_supported': smb_ports,
            'wsl_tools_available': self._check_smb_wsl_tools(),
            'nmap_integration': self.nmap_available,
            'aggressive_mode_supported': smb_available and self._check_smb_wsl_tools()
        }

        if smb_available:
            smb_scanner = self.scanners[445]  # Get SMB scanner instance
            if hasattr(smb_scanner, 'test_wsl_nmap'):
                status['wsl_nmap_test'] = smb_scanner.test_wsl_nmap()
            if hasattr(smb_scanner, 'test_wsl_enum4linux'):
                status['wsl_enum4linux_test'] = smb_scanner.test_wsl_enum4linux()

        return status

    def get_snmp_scanner_status (self)-> Dict[str, Any]:
        """Get SNMP scanner specific status"""
        snmp_ports = [161]
        snmp_available = all(port in scanner_manager.scanners for port in snmp_ports)

        status = {
            'snmp_scanner_available': snmp_available,
            'snmp_ports_supported': snmp_ports,
            'udp_scanning_supported': True,
            'community_brute_force_supported': snmp_available,
            'windows_enumeration_supported': snmp_available,
            'nmap_integration': scanner_manager.nmap_available,
            'aggressive_mode_supported': snmp_available and scanner_manager.nmap_available
        }

        # Check WSL availability for enhanced nmap features
        try:
            import subprocess
            wsl_test = subprocess.run(['wsl', 'echo', 'test'],
                                      capture_output=True, text=True, timeout=5)
            status['wsl_available'] = wsl_test.returncode == 0
            status['wsl_nmap_available'] = status['wsl_available'] and scanner_manager.nmap_available
        except:
            status['wsl_available'] = False
            status['wsl_nmap_available'] = False

        if snmp_available:
            snmp_scanner = scanner_manager.scanners[161]  # Get SNMP scanner instance

            # Test SNMP scanner methods if available
            if hasattr(snmp_scanner, '_check_udp_connectivity'):
                status['udp_connectivity_test_available'] = True
            if hasattr(snmp_scanner, '_run_safe_snmp_scan'):
                status['safe_scan_available'] = True
            if hasattr(snmp_scanner, '_run_aggressive_snmp_scan'):
                status['aggressive_scan_available'] = True
            if hasattr(snmp_scanner, 'scan_aggressive'):
                status['aggressive_method_available'] = True

        return status


# Create global scanner manager instance
scanner_manager = ScannerManager()


# Convenience functions for import compatibility
def scan_service(ip: str, port: int, **kwargs) -> Dict[str, Any]:
    """Main scanning function"""
    return scanner_manager.scan_service(ip, port, **kwargs)


def get_supported_ports() -> List[int]:
    """Get supported ports"""
    return scanner_manager.get_supported_ports()


def get_scanner_info() -> Dict[str, List[int]]:
    """Get scanner information"""
    return scanner_manager.get_scanner_info()


def get_pre_scan_intelligence(target: str, target_type: str) -> Dict[str, Any]:
    """Get pre-scan intelligence"""
    return scanner_manager.get_pre_scan_intelligence(target, target_type)


def generate_scan_plan(target: str, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate scan plan"""
    return scanner_manager.generate_scan_plan(target, intelligence_data)


def get_integration_status() -> Dict[str, Any]:
    """Get integration status"""
    return scanner_manager.get_integration_status()


def initialize_integrations(shodan_api_key: str = None, vulners_api_key: str = None):
    """Initialize integrations"""
    return scanner_manager.initialize_integrations(shodan_api_key, vulners_api_key)


def enhanced_scan_service(ip: str, port: int, **kwargs) -> Dict[str, Any]:
    """Enhanced scan service"""
    return scanner_manager.enhanced_scan_service(ip, port, **kwargs)


def bulk_scan_with_intelligence(targets: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
    """Bulk scan with intelligence"""
    return scanner_manager.bulk_scan_with_intelligence(targets, **kwargs)


def quick_intelligence_lookup(target: str, target_type: str = 'ip') -> Dict[str, Any]:
    """Quick intelligence lookup"""
    return scanner_manager.quick_intelligence_lookup(target, target_type)


def get_enhanced_capabilities() -> Dict[str, Any]:
    """Get enhanced capabilities"""
    return scanner_manager.get_enhanced_capabilities()


def validate_scan_target(target: str, target_type: str = 'ip') -> Dict[str, Any]:
    """Validate scan target"""
    return scanner_manager.validate_scan_target(target, target_type)


def check_service_health() -> Dict[str, Any]:
    """Check service health"""
    return scanner_manager.check_service_health()


def passive_discovery(target: str, port_range: str = '1-1000') -> Dict[str, Any]:
    """Passive discovery"""
    return scanner_manager.passive_discovery(target, port_range)


def enhanced_vulnerability_scan(target: str, port: int, service_type: str = None) -> Dict[str, Any]:
    """Enhanced vulnerability scan"""
    return scanner_manager.enhanced_vulnerability_scan_with_nmap(target, port, service_type)


def scan_service_aggressive(ip: str, port: int, **kwargs) -> Dict[str, Any]:
    """Aggressive scan service"""
    return scanner_manager.scan_service_aggressive(ip, port, **kwargs)


def get_smb_scanner_status() -> Dict[str, Any]:
    """Get SMB scanner status"""
    return scanner_manager.get_smb_scanner_status()