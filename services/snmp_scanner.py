import socket
import time
import subprocess
import re
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner

# SNMP Scanner using nmap NSE scripts
SNMP_NMAP_MODE = True
print("🎯 SNMP Scanner: Using nmap NSE scripts for comprehensive SNMP enumeration")


class SNMPScanner(BaseScanner):
    """SNMP Scanner with nmap NSE scripts - Normal and Aggressive modes"""

    def __init__(self, timeout: int = 10):
        super().__init__(timeout)
        self.common_communities = [
            'public', 'private', 'community', 'snmp', 'read', 'write',
            'admin', 'manager', 'cisco', 'password', '123456', 'default'
        ]

    def get_supported_ports(self) -> List[int]:
        return [161]  # SNMP

    def get_service_name(self) -> str:
        return "SNMP"

    def scan(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Standard SNMP scanning - Basic information gathering"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            # Step 1: Basic connectivity check (UDP)
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self._check_udp_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            # Step 2: Run safe nmap SNMP scan
            self.mark_step_completed(results, 'nmap_scan')
            nmap_results = self._run_safe_snmp_scan(ip, port)
            results['nmap_data'] = nmap_results

            if nmap_results.get('error'):
                return self.create_failed_result(ip, port,
                                                 f"SNMP scan failed: {nmap_results['error']}")

            # Extract service info from nmap
            self.update_service_info(results, nmap_results.get('service_info', {}))
            results['banner'] = nmap_results.get('banner', '')

            # Step 3: Parse nmap script results for advanced findings
            self.mark_step_completed(results, 'script_analysis')
            script_findings = self._parse_snmp_scripts(nmap_results, aggressive=False)
            results['advanced_findings'].update(script_findings)

            # Step 4: Security assessment from nmap results
            self.mark_step_completed(results, 'vulnerability')
            security_info = self._assess_snmp_security(nmap_results, script_findings, aggressive=False)
            results['vulnerabilities'] = security_info.get('vulnerabilities', [])
            results['recommendations'] = security_info.get('recommendations', [])

            return self.finalize_results(results, success=True)

        except Exception as e:
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def scan_aggressive(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Aggressive SNMP scanning - All scripts including brute force"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            normal_results = kwargs.get('normal_scan_results')
            print(f"🎯 Starting SNMP Aggressive Scan with all nmap scripts...")

            # Step 1: Basic connectivity check
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self._check_udp_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            # Step 2: Run aggressive nmap SNMP scan
            self.mark_step_completed(results, 'aggressive_nmap_scan')
            nmap_results = self._run_aggressive_snmp_scan(ip, port)
            results['nmap_data'] = nmap_results
            results['scan_mode'] = 'aggressive'

            if nmap_results.get('error'):
                return self.create_failed_result(ip, port,
                                                 f"Aggressive SNMP scan failed: {nmap_results['error']}")

            # Extract enhanced service info
            self.update_service_info(results, nmap_results.get('service_info', {}))
            results['banner'] = nmap_results.get('banner', '')

            # Step 3: Parse aggressive nmap script results
            self.mark_step_completed(results, 'aggressive_script_analysis')
            script_findings = self._parse_snmp_scripts(nmap_results, aggressive=True)
            results['advanced_findings'].update(script_findings)

            # Step 4: Enhanced security assessment
            self.mark_step_completed(results, 'aggressive_vulnerability')
            security_info = self._assess_snmp_security(nmap_results, script_findings, aggressive=True)
            results['vulnerabilities'] = security_info.get('vulnerabilities', [])
            results['recommendations'] = security_info.get('recommendations', [])

            return self.finalize_results(results, success=True)

        except Exception as e:
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def _check_udp_connectivity(self, ip: str, port: int) -> Dict[str, Any]:
        """Check UDP connectivity for SNMP"""
        connectivity_info = {
            'accessible': False,
            'response_time': None,
            'protocol': 'UDP',
            'method': 'socket_test'
        }

        try:
            start_time = time.time()

            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Send basic SNMP request (GetRequest for system.sysDescr.0)
            snmp_request = bytes([
                0x30, 0x26,  # SEQUENCE, length 38
                0x02, 0x01, 0x00,  # INTEGER version (0 = SNMPv1)
                0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # OCTET STRING "public"
                0xa0, 0x19,  # GetRequest PDU
                0x02, 0x01, 0x01,  # request-id
                0x02, 0x01, 0x00,  # error-status
                0x02, 0x01, 0x00,  # error-index
                0x30, 0x0e,  # VarBindList
                0x30, 0x0c,  # VarBind
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # OID 1.3.6.1.2.1.1.1.0
                0x05, 0x00  # NULL
            ])

            sock.sendto(snmp_request, (ip, port))
            response, addr = sock.recvfrom(1024)

            response_time = round((time.time() - start_time) * 1000, 2)

            if response and len(response) > 0:
                connectivity_info['accessible'] = True
                connectivity_info['response_time'] = response_time
                connectivity_info['snmp_response_detected'] = True

            sock.close()

        except socket.timeout:
            connectivity_info['failure_reason'] = 'SNMP request timed out'
        except Exception as e:
            connectivity_info['failure_reason'] = f'SNMP connectivity test failed: {str(e)}'

        return connectivity_info

    def _run_safe_snmp_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Run safe nmap scan with basic SNMP scripts"""
        try:
            # Safe SNMP nmap command
            cmd = [
                'wsl','nmap', '-sV','-sU', f'-p{port}',
                '--script', 'snmp-sysdescr,snmp-info,snmp-interfaces',
                '--script-timeout', '60s',
                '--host-timeout', '300s',
                ip
            ]

            print(f"🎯 Running safe SNMP nmap: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)

            if result.returncode != 0:
                error_msg = f"Nmap failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                return {'error': error_msg}

            parsed = self._parse_nmap_output(result.stdout, aggressive=False)
            parsed['command_used'] = ' '.join(cmd)
            parsed['tool_used'] = 'nmap_safe'
            parsed['scan_type'] = 'safe'

            return parsed

        except subprocess.TimeoutExpired:
            return {'error': 'SNMP nmap scan timed out after 6 minutes'}
        except Exception as e:
            return {'error': f'SNMP nmap execution failed: {str(e)}'}

    def _run_aggressive_snmp_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Run aggressive nmap scan with all SNMP scripts"""
        try:
            # Aggressive SNMP nmap command
            cmd = [
                'wsl','nmap', '-sU', f'-p{port}',
                '--script', 'snmp-*',
                '--script-args', 'snmp.version=all',
                '--script-timeout', '120s',
                '--host-timeout', '600s',
                ip
            ]

            print(f"🎯 Running aggressive SNMP nmap: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=720)

            if result.returncode != 0:
                error_msg = f"Aggressive SNMP nmap failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                return {'error': error_msg}

            parsed = self._parse_nmap_output(result.stdout, aggressive=True)
            parsed['command_used'] = ' '.join(cmd)
            parsed['tool_used'] = 'nmap_aggressive'
            parsed['scan_type'] = 'aggressive'

            return parsed

        except subprocess.TimeoutExpired:
            return {'error': 'Aggressive SNMP nmap scan timed out after 12 minutes'}
        except Exception as e:
            return {'error': f'Aggressive SNMP nmap execution failed: {str(e)}'}

    def _parse_nmap_output(self, nmap_output: str, aggressive: bool = False) -> Dict[str, Any]:
        """Parse SNMP nmap output"""
        parsed = {
            'service_info': {},
            'banner': '',
            'scripts': {},
            'raw_output': nmap_output,
            'formatted_for_display': self._format_snmp_output(nmap_output),
            'scan_mode': 'aggressive' if aggressive else 'safe'
        }

        lines = nmap_output.split('\n')

        for line in lines:
            line_stripped = line.strip()

            # Parse SNMP service line
            if '/udp' in line and 'snmp' in line.lower():
                parsed['service_info']['protocol'] = 'UDP'
                parsed['service_info']['service'] = 'SNMP'
                parsed['banner'] = line_stripped

            # Parse SNMP script results
            elif line_stripped.startswith('|_snmp-') or line_stripped.startswith('| snmp-'):
                script_name = self._extract_script_name(line_stripped)
                if script_name:
                    content = self._extract_script_content(line_stripped, script_name)
                    parsed['scripts'][script_name] = content

        return parsed

    def _extract_script_name(self, line: str) -> Optional[str]:
        """Extract script name from nmap output line"""
        try:
            if line.startswith('|_'):
                parts = line.split(':', 1)
                if len(parts) >= 1:
                    return parts[0].replace('|_', '').strip()
            elif line.startswith('| '):
                parts = line.split(':', 1)
                if len(parts) >= 1:
                    return parts[0].replace('| ', '').strip()
        except:
            pass
        return None

    def _extract_script_content(self, line: str, script_name: str) -> str:
        """Extract content from script output line"""
        try:
            content = line.replace(f'|_{script_name}:', '').replace(f'| {script_name}:', '').strip()
            return content if content else 'Script executed'
        except:
            return 'Script executed'

    def _parse_snmp_scripts(self, nmap_data: Dict[str, Any], aggressive: bool = False) -> Dict[str, Any]:
        """Parse SNMP script results into structured findings"""
        findings = {}
        scripts = nmap_data.get('scripts', {})
        raw_output = nmap_data.get('raw_output', '')

        # Parse system information
        if 'snmp-sysdescr' in scripts or 'snmp-info' in scripts:
            findings['system_info'] = self._parse_system_info(scripts, raw_output)

        # Parse interfaces
        if 'snmp-interfaces' in scripts:
            findings['network_interfaces'] = self._parse_interfaces(scripts['snmp-interfaces'], raw_output)

        if aggressive:
            # Parse brute force results
            if 'snmp-brute' in scripts:
                findings['brute_force_results'] = self._parse_snmp_brute_force(scripts['snmp-brute'], raw_output)

            # Parse Windows-specific findings
            windows_findings = self._parse_windows_snmp_findings(scripts, raw_output)
            if windows_findings:
                findings['windows_enumeration'] = windows_findings

            # Parse process and service findings
            process_findings = self._parse_process_findings(scripts, raw_output)
            if process_findings:
                findings['process_enumeration'] = process_findings

            # Parse network findings
            network_findings = self._parse_network_findings(scripts, raw_output)
            if network_findings:
                findings['network_enumeration'] = network_findings

        return findings

    def _parse_system_info(self, scripts: Dict[str, Any], raw_output: str) -> Dict[str, Any]:
        """Parse system information from SNMP"""
        system_info = {
            'system_description': None,
            'system_contact': None,
            'system_name': None,
            'system_location': None,
            'uptime': None
        }

        # Parse from snmp-sysdescr
        if 'snmp-sysdescr' in scripts:
            system_info['system_description'] = scripts['snmp-sysdescr']

        # Parse from snmp-info
        if 'snmp-info' in scripts:
            info_lines = scripts['snmp-info'].split('\n')
            for line in info_lines:
                line = line.strip()
                if 'Contact:' in line:
                    system_info['system_contact'] = line.split('Contact:', 1)[1].strip()
                elif 'Name:' in line:
                    system_info['system_name'] = line.split('Name:', 1)[1].strip()
                elif 'Location:' in line:
                    system_info['system_location'] = line.split('Location:', 1)[1].strip()
                elif 'Uptime:' in line:
                    system_info['uptime'] = line.split('Uptime:', 1)[1].strip()

        return system_info

    def _parse_interfaces(self, interfaces_result: str, raw_output: str) -> Dict[str, Any]:
        """Parse network interfaces from SNMP"""
        interfaces = {
            'total_interfaces': 0,
            'active_interfaces': [],
            'interface_details': []
        }

        lines = interfaces_result.split('\n')
        for line in lines:
            line = line.strip()
            if 'Interface' in line and ('up' in line.lower() or 'down' in line.lower()):
                interfaces['total_interfaces'] += 1
                if 'up' in line.lower():
                    interfaces['active_interfaces'].append(line)
                interfaces['interface_details'].append(line)

        return interfaces

    def _parse_snmp_brute_force(self, brute_result: str, raw_output: str) -> Dict[str, Any]:
        """Parse SNMP brute force results"""
        brute_force = {
            'communities_found': [],
            'brute_attempted': True,
            'success': False
        }

        if 'valid community' in brute_result.lower() or 'found' in brute_result.lower():
            brute_force['success'] = True

            # Extract community strings
            lines = brute_result.split('\n')
            for line in lines:
                if 'valid' in line.lower() or 'found' in line.lower():
                    # Try to extract community string
                    import re
                    community_match = re.search(r'community[:\s]+([^\s\n]+)', line, re.IGNORECASE)
                    if community_match:
                        community = community_match.group(1)
                        if community not in brute_force['communities_found']:
                            brute_force['communities_found'].append(community)

        return brute_force

    def _parse_windows_snmp_findings(self, scripts: Dict[str, Any], raw_output: str) -> Dict[str, Any]:
        """Parse Windows-specific SNMP findings"""
        windows_findings = {}

        # Windows services
        if 'snmp-win32-services' in scripts:
            windows_findings['services'] = self._parse_windows_services(scripts['snmp-win32-services'])

        # Windows shares
        if 'snmp-win32-shares' in scripts:
            windows_findings['shares'] = self._parse_windows_shares(scripts['snmp-win32-shares'])

        # Windows users
        if 'snmp-win32-users' in scripts:
            windows_findings['users'] = self._parse_windows_users(scripts['snmp-win32-users'])

        # Windows software
        if 'snmp-win32-software' in scripts:
            windows_findings['software'] = self._parse_windows_software(scripts['snmp-win32-software'])

        return windows_findings

    def _parse_windows_services(self, services_result: str) -> List[str]:
        """Parse Windows services from SNMP"""
        services = []
        lines = services_result.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('|'):
                services.append(line)
        return services[:20]  # Limit to first 20 services

    def _parse_windows_shares(self, shares_result: str) -> List[str]:
        """Parse Windows shares from SNMP"""
        shares = []
        lines = shares_result.split('\n')
        for line in lines:
            line = line.strip()
            if line and '\\' in line:
                shares.append(line)
        return shares

    def _parse_windows_users(self, users_result: str) -> List[str]:
        """Parse Windows users from SNMP"""
        users = []
        lines = users_result.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('|'):
                users.append(line)
        return users[:15]  # Limit to first 15 users

    def _parse_windows_software(self, software_result: str) -> List[str]:
        """Parse Windows software from SNMP"""
        software = []
        lines = software_result.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('|'):
                software.append(line)
        return software[:10]  # Limit to first 10 software entries

    def _parse_process_findings(self, scripts: Dict[str, Any], raw_output: str) -> Dict[str, Any]:
        """Parse process-related findings"""
        process_findings = {}

        if 'snmp-processes' in scripts:
            processes = []
            lines = scripts['snmp-processes'].split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('|'):
                    processes.append(line)
            process_findings['running_processes'] = processes[:15]  # Limit to first 15

        return process_findings

    def _parse_network_findings(self, scripts: Dict[str, Any], raw_output: str) -> Dict[str, Any]:
        """Parse network-related findings"""
        network_findings = {}

        if 'snmp-netstat' in scripts:
            connections = []
            lines = scripts['snmp-netstat'].split('\n')
            for line in lines:
                line = line.strip()
                if line and ('TCP' in line or 'UDP' in line):
                    connections.append(line)
            network_findings['network_connections'] = connections[:10]  # Limit to first 10

        return network_findings

    def _assess_snmp_security(self, nmap_data: Dict[str, Any], script_findings: Dict[str, Any],
                              aggressive: bool = False) -> Dict[str, Any]:
        """Assess SNMP security based on findings"""
        vulnerabilities = []
        recommendations = []

        # Check for basic SNMP access
        if script_findings.get('system_info'):
            vulnerabilities.append({
                'id': 'SNMP-ACCESS-001',
                'severity': 'Medium',
                'title': 'SNMP Service Accessible',
                'description': 'SNMP service is accessible and responding to queries',
                'recommendation': 'Restrict SNMP access to authorized management systems only',
                'source': 'nmap_nse',
                'detection_method': 'snmp-info'
            })

        if aggressive:
            # Check for brute force success
            if script_findings.get('brute_force_results', {}).get('success'):
                brute_results = script_findings['brute_force_results']
                vulnerabilities.append({
                    'id': 'SNMP-BRUTE-001',
                    'severity': 'High',
                    'title': 'Weak SNMP Community Strings Found',
                    'description': f'Discovered SNMP community strings: {", ".join(brute_results.get("communities_found", []))}',
                    'recommendation': 'Use strong, non-default SNMP community strings and implement SNMPv3',
                    'source': 'nmap_nse_aggressive',
                    'detection_method': 'snmp-brute'
                })

            # Check for Windows enumeration
            if script_findings.get('windows_enumeration'):
                windows_enum = script_findings['windows_enumeration']
                if windows_enum.get('users') or windows_enum.get('services'):
                    vulnerabilities.append({
                        'id': 'SNMP-ENUM-001',
                        'severity': 'Medium',
                        'title': 'SNMP Information Disclosure',
                        'description': 'SNMP allows enumeration of sensitive system information',
                        'recommendation': 'Disable SNMP or use SNMPv3 with authentication and encryption',
                        'source': 'nmap_nse_aggressive',
                        'detection_method': 'snmp-win32-*'
                    })

        # Standard recommendations
        recommendations.extend([
            'Upgrade to SNMPv3 with authentication and encryption',
            'Use strong, non-default community strings',
            'Implement access control lists (ACLs) for SNMP',
            'Disable SNMP if not required for network management',
            'Monitor SNMP access logs for suspicious activity',
            'Use read-only community strings where possible'
        ])

        return {
            'vulnerabilities': vulnerabilities,
            'recommendations': list(set(recommendations))
        }

    def _format_snmp_output(self, nmap_output: str) -> str:
        """Format SNMP nmap output for display"""
        lines = nmap_output.split('\n')
        important_lines = []

        for line in lines:
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in [
                'port', 'state', 'service', 'snmp-', 'community', 'system',
                'interface', 'process', 'user', 'service', 'software'
            ]):
                important_lines.append(line)

        return '\n'.join(important_lines) if important_lines else nmap_output

    def _extract_server_type(self, line: str) -> str:
        """Extract SNMP server type from nmap output"""
        line_lower = line.lower()
        if 'windows' in line_lower:
            return 'Windows SNMP'
        elif 'linux' in line_lower:
            return 'Linux SNMP'
        elif 'cisco' in line_lower:
            return 'Cisco SNMP'
        elif 'net-snmp' in line_lower:
            return 'Net-SNMP'
        else:
            return 'SNMP Service'

    def _extract_version(self, line: str) -> str:
        """Extract SNMP version from nmap output"""
        # SNMP versions are typically v1, v2c, v3
        if 'v3' in line.lower():
            return 'SNMPv3'
        elif 'v2c' in line.lower():
            return 'SNMPv2c'
        elif 'v1' in line.lower():
            return 'SNMPv1'
        else:
            return 'Unknown'